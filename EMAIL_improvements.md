Subject: SOC-X Cloud Simulator — Recommendation Template Improvements Now Available

Hi all,

I've wired up a set of improvements to the SOC-X Cloud Recommendation Simulator
around the recommendation-template workflow. Here's a summary of what's new and
how to use it.

1. Multiple templates
---------------------
You are no longer limited to a single template. You can now create as many
recommendation templates as you need, and every enabled template that matches
an incoming request contributes its rules to the response.
- A template with **no request networks** acts as a catch-all (matches any
  request that isn't a pinned network).
- A template **with** networks matches only requests for those exact networks.
- The destination network in the emitted rules always matches the incoming
  request.
UI: Tab 2 ("Recommendation templates") → "New template".
API: GET/POST `/ui/templates`, PUT/DELETE `/ui/templates/{template_id}`.

2. Unique rule IDs per rule
---------------------------
Every rule now carries its own globally-unique `ruleId`. IDs are derived from
each template's unique id (uuid4) plus the network and rule index, so:
- rules from a newly created template can never collide with older ones, and
- a single response never contains duplicate rule IDs.
"View JSON" in the UI shows the real, generated rule IDs.

3. Add / edit / disable recommendation templates
-------------------------------------------------
Full lifecycle management for templates:
- **Add**: create new templates from the UI or API.
- **Edit**: update name, networks, and rules.
- **Disable**: toggle a template's `enabled` flag — disabled templates are
  skipped at request time and fall back to learning/auto-generation.
- **Delete**: remove a template entirely (returns 404 if it doesn't exist).
Templates are persisted to `data/response_template.json`, so they survive
restarts and are shared across all Cyber Controllers.

4. Scale testing
----------------
New tooling to generate and serve large recommendation sets for scale/load
testing:
- `POST /ui/scale/preview` — reports capacity and a sample without persisting.
- `POST /ui/scale/generate` — materializes a set (bound to a CC IP).
- `POST /ui/scale/download` — streams very large sets so they don't have to be
  held in memory.
Guardrails: sets larger than `SCALE_MAX_SERVE` (default 50,000) use the
streaming download path, and a single download is hard-capped at
`SCALE_MAX_DOWNLOAD` (default 2,000,000).

All of the above is covered by the CI test suite (`tests/test_ci.py`),
including unique-rule-id checks, multi-template coexistence, template
add/edit/disable/delete, and scale preview/generate scenarios.

Happy to walk anyone through it or take feedback.

Thanks,
[Your name]

