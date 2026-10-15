# 🚀 Ecommerce AI Audit Agent — Backend Architecture & Integration Specification

This document serves as a comprehensive technical context and integration blueprint for the **Ecommerce AI Audit Agent** backend repository ([haseeb1984/ecommerce-audit-agent](https://github.com/haseeb1984/ecommerce-audit-agent)).

Use this documentation to understand the existing Python FastAPI + Supabase + Groq architecture and build the accompanying **WordPress Licensing Plugin**, **SaaS Frontend Dashboard**, and **Email Delivery Engine**.

## 💳 Pricing Tiers & Packages Architecture

The backend supports a multi-tier SaaS model with the following quota structures, feature gates, and access levels:

| Tier / Package | Price | Monthly Quota | Depth Options | Key Features & Access | 
| ----- | ----- | ----- | ----- | ----- | 
| **Starter Tier** | \$29 / mo | 50 Audits / mo | Standard Speed | Core Web Vitals, Basic Performance & SEO Analysis | 
| **Agency / Pro** | \$79 / mo | 250 Audits / mo | Standard + Dossier | Full Conversion Leak Dossiers, Detailed UX Breakdowns | 
| **Whitelabel / Enterprise** | \$199 / mo | Unlimited / Custom | Standard + Dossier | Agency PDF Branding (Custom Logo/Header), Direct FastAPI Key Access | 

### Feature Gate Logic for Frontend & Plugin:

1. **Conversion Dossier Access:** Only available for `agency` and `whitelabel` tiers (`audit_depth: "dossier"`).

2. **Whitelabel Custom Branding:** Enabled exclusively for `whitelabel` tier users (allows passing agency name and logo to PDF generation endpoints).

3. **API Access:** FastApi integration keys (`apk_...`) are provisioned exclusively for `whitelabel` tier users.

## 📐 System Architecture Overview

```
[ User / Dashboard ] ──> [ WordPress Licensing Plugin ] ──> [ FastAPI Backend (Vercel) ]
                                                                     │
                                    ┌────────────────────────────────┼────────────────────────────────┐
                                    ▼                                ▼                                ▼
                          [ PageSpeed / Scraper ]             [ Groq AI Engine ]             [ Supabase DB & Storage ]
                                    │                                │                                │
                                    └────────────────────────────────┴────────────────────────────────┘
                                                                     │
                                                                     ▼
                                                   [ PDF Generation & Email Dispatch ]


```

## 🛠️ Tech Stack Breakdown

* **Backend Framework:** FastAPI (Python 3.10+) hosted on Vercel Serverless.

* **AI Orchestration:** Groq API (`llama-3.3-70b-versatile` / `mixtral-8x7b`) for rapid e-commerce store analysis.

* **Database & Storage:** Supabase PostgreSQL (Audits, Quota, User Sync) & Supabase Storage Bucket (`audit-reports`).

* **Licensing & Billing Gateways:** WordPress (WooCommerce / Custom DB) + Paddle API integration (Sandbox/Production).

* **PDF & Email Engine:** WeasyPrint/ReportLab PDF Builder + Resend / SendGrid / SMTP API for automatic PDF delivery.

## 📡 Primary API Endpoints Specification

### 1. Execute Store Audit

* **Endpoint:** `POST /api/v1/audit`

* **Headers:**

  * `Content-Type: application/json`

  * `Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>`

* **Request Body:**

```
{
  "target_url": "https://example-store.com",
  "depth": "standard", // "standard" or "dossier"
  "user_email": "client@example.com",
  "user_id": "wp_user_123",
  "tier": "whitelabel", // "starter", "agency", or "whitelabel"
  "agency_branding": {
    "name": "Acme Marketing Agency",
    "logo_url": "https://example.com/logo.png"
  }
}

```

* **Expected Response (`200 OK`):**

```
{
  "status": "success",
  "audit_id": "aud_987654321",
  "target_url": "https://example-store.com",
  "report_url": "https://<supabase-id>.supabase.co/storage/v1/object/public/audit-reports/report_aud_987654321.pdf",
  "summary": {
    "performance_score": 84,
    "seo_health": 91,
    "conversion_friction": "High LCP latency on mobile product pages."
  },
  "quota_info": {
    "quota_used": 12,
    "quota_limit": 250,
    "quota_remaining": 238
  }
}

```

### 2. Verify Quota & License Key Status

* **Endpoint:** `POST /api/v1/license/verify`

* **Request Body:**

```
{
  "license_key": "LICENSE-XXXX-YYYY-ZZZZ",
  "domain": "https://example-store.com"
}

```

* **Expected Response (`200 OK`):**

```
{
  "valid": true,
  "tier": "agency",
  "quota_limit": 250,
  "quota_used": 12,
  "expires_at": "2027-01-01T00:00:00Z"
}

```

## 🗄️ Database Schemas (Supabase / PostgreSQL)

### `audits` Table

```
CREATE TABLE public.audits (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    depth TEXT DEFAULT 'standard',
    performance_score INT,
    seo_score INT,
    report_pdf_url TEXT,
    raw_json_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

```

### `user_quotas` Table

```
CREATE TABLE public.user_quotas (
    user_id TEXT PRIMARY KEY,
    user_email TEXT NOT NULL,
    license_key TEXT UNIQUE,
    plan_tier TEXT DEFAULT 'starter', -- 'starter', 'agency', 'whitelabel'
    quota_limit INT DEFAULT 50,
    quota_used INT DEFAULT 0,
    agency_name TEXT,
    agency_logo TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

```

## 🔑 Key Integration Requirements for Frontend & WordPress

### 1. WordPress Licensing Plugin Tasks:

* Sync WordPress Users and Metadata (`_ai_audit_tier`, `_ai_audit_quota_used`, `_ai_audit_quota_limit`) with Supabase / FastAPI.

* Hook into Paddle webhook events (or WooCommerce) to update user tiers upon purchase (`starter`, `agency`, `whitelabel`).

* Render the Front-end `/dashboard` interface restricting access to WP-Admin.

### 2. PDF Delivery Workflow:

* Upon audit completion, the backend builds a styled PDF report (applying agency branding if Whitelabel).

* Uploads the PDF directly to Supabase Storage bucket `audit-reports`.

* Sends the PDF via email attachment/link using Resend/SendGrid.

* Returns the public `report_url` to the client dashboard for immediate UI rendering and direct download.

### 3. Client Frontend UI Expectations:

* Input bar for entering Store URL.

* Diagnostic Depth dropdown (`Standard` vs `Full Dossier`, locked based on tier).

* Whitelabel Branding control section (enabled only for Whitelabel tier).

* Audit Summary Widget with metrics & direct **"Download PDF Audit Report"** button.

* Dynamic Quota consumption bar (e.g., `12 / 250 Audits Used`).

## 🎯 Direct Prompt Instructions for AI / Developer

> **Prompt to pass:** "I have an existing FastAPI + Groq AI + Supabase backend repository hosted at `https://github.com/haseeb1984/ecommerce-audit-agent`. Please review the system specification document above and help me build:
>
> 1. The **WordPress Licensing & SaaS Bridge Plugin** (handling Paddle checkout, tier assignments for Starter/Agency/Whitelabel, license keys, quota sync, and REST API calls to the backend).
>
> 2. The **Frontend User Dashboard UI** (URL input, feature gates for Dossier and Whitelabel branding, quota bar, PDF download link display).
>
> 3. Fix any timeout or API communication issues between WordPress, Paddle Sandbox, and FastAPI."