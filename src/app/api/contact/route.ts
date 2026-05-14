import { NextRequest, NextResponse } from 'next/server'
import { Resend } from 'resend'

// Escape HTML to prevent XSS in email body
const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

// Simple rate limiting via in-memory map (resets on cold start)
const rateMap = new Map<string, { count: number; reset: number }>()
const RATE_LIMIT = 5 // max requests
const RATE_WINDOW = 60_000 // per 60 seconds

function checkRateLimit(ip: string): boolean {
    const now = Date.now()
    const entry = rateMap.get(ip)
    if (!entry || now > entry.reset) {
        rateMap.set(ip, { count: 1, reset: now + RATE_WINDOW })
        return true
    }
    if (entry.count >= RATE_LIMIT) return false
    entry.count++
    return true
}

export async function POST(request: NextRequest) {
    // Rate limiting
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown'
    if (!checkRateLimit(ip)) {
        return NextResponse.json({ error: 'Too many requests. Please wait a minute.' }, { status: 429 })
    }

    // Body size limit — reject anything over 10KB
    const contentLength = request.headers.get('content-length')
    if (contentLength && parseInt(contentLength) > 10_000) {
        return NextResponse.json({ error: 'Request too large' }, { status: 413 })
    }

    // Parse body safely
    let body: Record<string, unknown>
    try {
        body = await request.json()
    } catch {
        return NextResponse.json({ error: 'Invalid request body' }, { status: 400 })
    }

    const { name, email, phone, service, message } = body

    // Type validation
    if (
        typeof name !== 'string' || typeof email !== 'string' ||
        typeof phone !== 'string' || typeof service !== 'string' ||
        typeof message !== 'string'
    ) {
        return NextResponse.json({ error: 'Invalid field types' }, { status: 400 })
    }

    // Length validation
    if (!name.trim() || !email.trim() || !message.trim()) {
        return NextResponse.json({ error: 'Required fields missing' }, { status: 400 })
    }
    if (name.length > 100 || email.length > 200 || phone.length > 20 ||
        service.length > 100 || message.length > 2000) {
        return NextResponse.json({ error: 'Field too long' }, { status: 400 })
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
        return NextResponse.json({ error: 'Invalid email address' }, { status: 400 })
    }

    const key = process.env.RESEND_API_KEY
    if (!key) {
        return NextResponse.json({ error: 'Server misconfiguration' }, { status: 500 })
    }

    const resend = new Resend(key)

    try {
        await resend.emails.send({
            from: 'onboarding@resend.dev',
            to: process.env.CONTACT_EMAIL || 'hello@rturox.com',
            subject: `New enquiry from ${esc(name)}`,
            html: `
                <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px">
                    <h2 style="color:#A855F7;margin-bottom:16px">New Contact Enquiry</h2>
                    <table style="width:100%;border-collapse:collapse">
                        <tr><td style="padding:8px 0;color:#737373;width:120px">Name</td><td style="padding:8px 0;color:#fff">${esc(name)}</td></tr>
                        <tr><td style="padding:8px 0;color:#737373">Email</td><td style="padding:8px 0;color:#fff">${esc(email)}</td></tr>
                        <tr><td style="padding:8px 0;color:#737373">Phone</td><td style="padding:8px 0;color:#fff">${esc(phone)}</td></tr>
                        <tr><td style="padding:8px 0;color:#737373">Service</td><td style="padding:8px 0;color:#fff">${esc(service)}</td></tr>
                        <tr><td style="padding:8px 0;color:#737373;vertical-align:top">Message</td><td style="padding:8px 0;color:#fff;white-space:pre-wrap">${esc(message)}</td></tr>
                    </table>
                </div>
            `,
        })
        return NextResponse.json({ success: true })
    } catch {
        return NextResponse.json({ error: 'Failed to send email' }, { status: 500 })
    }
}
