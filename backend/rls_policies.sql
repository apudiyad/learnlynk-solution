-- LearnLynk Tech Test - Task 2: RLS Policies on leads

alter table public.leads enable row level security;

-- Example helper: assume JWT has tenant_id, user_id, role.
-- You can use: current_setting('request.jwt.claims', true)::jsonb

-- TODO: write a policy so:
-- - counselors see leads where they are owner_id OR in one of their teams
-- - admins can see all leads of their tenant


-- Example skeleton for SELECT (replace with your own logic):

create policy "leads_select_policy"
on public.leads
for select
using (
  (
    auth.jwt()->>'role' = 'admin'
    and tenant_id::text = auth.jwt()->>'tenant_id'
  )
  or
  (
    auth.jwt()->>'role' = 'counselor'
    and tenant_id::text = auth.jwt()->>'tenant_id'
    and (
      owner_id::text = auth.jwt()->>'user_id'
      or exists (
        select 1
        from user_teams ut
        join teams t on t.id = ut.team_id
        where ut.user_id::text = auth.jwt()->>'user_id'
        and t.tenant_id = leads.tenant_id
      )
    )
  )
);

-- TODO: add INSERT policy that:
-- - allows counselors/admins to insert leads for their tenant
-- - ensures tenant_id is correctly set/validated

create policy "leads_insert_policy"
on public.leads
for insert
with check (
  auth.jwt()->>'role' in ('admin','counselor')
  and tenant_id::text = auth.jwt()->>'tenant_id'
);