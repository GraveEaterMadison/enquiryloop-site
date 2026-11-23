# EnquiryLoop

Self-service admissions CRM for tutors, academies, coaching centres and small education businesses.

## Implemented in this release
- Responsive marketing site and self-service signup/sign-in.
- Supabase Auth integration (email + password).
- One private workspace created for each new account.
- Self-service account deletion through an authenticated Edge Function (blocked when other workspace members would be affected).
- Cloud-backed enquiry management, search, filters and CSV import/export (2 MB / 500-row import cap, validation, spreadsheet-formula-safe exports).
- Workspace-level PostgreSQL row-level security policies using a private, non-exposed membership helper and least-privilege browser grants.
- Free-plan limit of 50 enquiries enforced by a database trigger.
- Billing schema foundation; paid checkout is **not connected yet**.

## Connect the backend
1. Create a project at https://supabase.com.
2. Run the complete `supabase/schema.sql` in the Supabase SQL Editor.
3. Edit `app/config.js`: replace `YOUR_SUPABASE_PROJECT_URL` and `YOUR_SUPABASE_ANON_KEY` with the project URL and anon/public key.
4. In Supabase → Authentication → URL Configuration, set the Site URL to `https://graveeatermadison.github.io` and add `https://graveeatermadison.github.io/enquiryloop-site/app/` as a redirect URL.
5. Test with two separate accounts and confirm each account can only see its own workspace data.

The anon key is designed for browser use with RLS. **Never put a Supabase service_role key or payment secret in browser code or GitHub.**

## Plans
- Free: 50 enquiries/workspace.
- Starter: proposed ₹199/month.
- Pro: proposed ₹499/month.

Prices are proposals, not validated market prices. Paid checkout is not active. A server-side payment integration, verified webhooks, subscription management, cancellation/refund flows and testing are required before paid plans can be sold.

## Before production
- Configure Supabase credentials and test workspace isolation.
- Enable leaked-password protection in Supabase Auth; add account deletion and support procedures.
- Configure reliable backups, restore tests, monitoring and error reporting.
- Complete legal review of privacy notice, terms, retention and applicable Indian privacy obligations.
- Add secure billing before enabling paid subscriptions.

Student/customer names, phone numbers, emails and notes are personal information. Use synthetic test data until security policies, safeguards and appropriate notices have been reviewed.