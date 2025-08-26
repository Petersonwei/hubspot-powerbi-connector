# OAuth Configuration Guide

## Required Environment Variables

Set these environment variables in your hosting platform (Render, Heroku, etc.):

```
HUBSPOT_CLIENT_ID=your-client-id-here
HUBSPOT_CLIENT_SECRET=your-client-secret-here
OAUTH_REDIRECT_URI=https://your-deployed-url.com/?action=callback
OAUTH_SCOPES=crm.objects.companies.read crm.objects.contacts.read crm.objects.deals.read crm.objects.owners.read oauth
```

**Note:** The `OAUTH_SCOPES` variable is optional. If not set, the connector will use the default scopes listed above.

## HubSpot App Setup

1. Go to [HubSpot Developer Portal](https://developers.hubspot.com/)
2. Create a new app or use existing app
3. Get your Client ID and Client Secret
4. Set redirect URI to: `https://your-deployed-url.com/?action=callback`

## Required Scopes

The connector requests these scopes:
- `crm.objects.contacts.read`
- `crm.objects.deals.read` 
- `crm.objects.companies.read`
- `crm.objects.tasks.read`
- `crm.objects.meetings.read`
- `crm.objects.calls.read`
- `crm.objects.tickets.read`

## OAuth Flow

1. Navigate to: `https://your-deployed-url.com/?action=authorize`
2. Complete HubSpot authorization
3. Callback will store OAuth token
4. Power BI can now access data without API key

## Power BI Changes

With OAuth, you NO LONGER need to pass `hapikey_token` parameter.
Only pass:
- `token` (your internal auth token)
- `account_id` (HubSpot account ID)