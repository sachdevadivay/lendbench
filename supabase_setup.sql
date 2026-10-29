-- Lendbench database setup. Run once in Supabase > SQL Editor, on a fresh project.
-- Order: A tables, B helper functions, C security rules (RLS), D triggers, E seed data (after creating users).

-- A. TABLES -----------------------------------------------------------------
create extension if not exists btree_gist;
create table profiles(id uuid primary key references auth.users on delete cascade, name text not null,
  role text not null default 'user' check (role in ('user','owner','manager','admin')),
  dept text, verified boolean default false, paused boolean default false, need boolean default false);
create table resources(id uuid primary key default gen_random_uuid(), owner_id uuid references profiles(id),
  name text not null, category text, location text, requires text[] default '{}', max_hrs int default 3,
  monthly_cap int default 8, deposit int default 0, supervised boolean default false, rules text, active boolean default true);
create table resource_managers(resource_id uuid references resources(id) on delete cascade, user_id uuid references profiles(id), primary key(resource_id,user_id));
create table credentials(user_id uuid references profiles(id), cert text, status text default 'pending', primary key(user_id,cert));
create table bookings(id uuid primary key default gen_random_uuid(), resource_id uuid references resources(id), user_id uuid references profiles(id),
  date date not null, start_hr int not null, hrs int not null, purpose text,
  status text default 'pending' check (status in ('pending','waitlisted','approved','rejected','cancelled','checked_in','returned')),
  reason text, score int, parts jsonb, ci jsonb, ret jsonb, overdue boolean default false, late_cancel boolean default false,
  created_at timestamptz default now(),
  slot tsrange generated always as (tsrange(date::timestamp + make_interval(hours => start_hr), date::timestamp + make_interval(hours => start_hr + hrs))) stored,
  exclude using gist (resource_id with =, slot with &&) where (status in ('approved','checked_in')));  -- no double booking, ever
create table incidents(id uuid primary key default gen_random_uuid(), booking_id uuid references bookings(id), resource_id uuid, user_id uuid,
  reported_by uuid, kind text, description text, status text default 'open', decision text, decision_note text, created_at timestamptz default now());
create table audit_log(id bigserial primary key, actor uuid, action text, detail text, booking_id uuid, resource_id uuid, created_at timestamptz default now());
create table notifications(id bigserial primary key, user_id uuid, msg text, read boolean default false, created_at timestamptz default now());
-- Shows only WHICH slots are taken (no names or purposes), so students can see conflicts without seeing others' data.
create view busy_slots as select resource_id,date,start_hr,hrs from bookings where status in ('approved','checked_in');
grant select on busy_slots to authenticated;

-- B. HELPER FUNCTIONS -------------------------------------------------------
create function is_reviewer(rid uuid) returns boolean language sql security definer stable as $$
  select exists(select 1 from resources where id=rid and owner_id=auth.uid())
      or exists(select 1 from resource_managers where resource_id=rid and user_id=auth.uid()) $$;
create function is_admin() returns boolean language sql security definer stable as $$
  select exists(select 1 from profiles where id=auth.uid() and role='admin') $$;
create function pause_user(uid uuid) returns void language sql security definer as $$
  update profiles set paused=true where id=uid and (select role from profiles where id=auth.uid()) in ('owner','manager') $$;

-- C. ROW LEVEL SECURITY: the database itself enforces who sees and changes what
alter table profiles enable row level security; alter table resources enable row level security;
alter table resource_managers enable row level security; alter table credentials enable row level security;
alter table bookings enable row level security; alter table incidents enable row level security;
alter table audit_log enable row level security; alter table notifications enable row level security;
create policy "read profiles" on profiles for select to authenticated using (true);
create policy "admin edits profiles" on profiles for update using (is_admin());
create policy "read resources" on resources for select to authenticated using (true);
create policy "verified owners list" on resources for insert with check (owner_id=auth.uid() and exists(select 1 from profiles where id=auth.uid() and verified and role='owner'));
create policy "owner updates listing" on resources for update using (owner_id=auth.uid());
create policy "read managers" on resource_managers for select to authenticated using (true);
create policy "owner adds managers" on resource_managers for insert with check (exists(select 1 from resources where id=resource_id and owner_id=auth.uid()));
create policy "read credentials" on credentials for select using (user_id=auth.uid() or exists(select 1 from profiles where id=auth.uid() and role in ('owner','manager','admin')));
create policy "request credential" on credentials for insert with check (user_id=auth.uid());
create policy "verify credential" on credentials for update using (exists(select 1 from profiles where id=auth.uid() and role in ('owner','manager')));
create policy "read bookings" on bookings for select using (user_id=auth.uid() or is_reviewer(resource_id) or is_admin());
create policy "students request" on bookings for insert with check (user_id=auth.uid() and status in ('pending','waitlisted'));
create policy "reviewers decide" on bookings for update using (is_reviewer(resource_id));
create policy "users update own" on bookings for update using (user_id=auth.uid());
create policy "read incidents" on incidents for select using (user_id=auth.uid() or is_reviewer(resource_id) or is_admin());
create policy "report incident" on incidents for insert with check (reported_by=auth.uid());
create policy "resolve incident" on incidents for update using (is_reviewer(resource_id));
create policy "read audit" on audit_log for select using (is_admin() or actor=auth.uid() or is_reviewer(resource_id));  -- no insert/update/delete policy: history cannot be edited from the browser
create policy "own notifications" on notifications for select using (user_id=auth.uid());
create policy "mark read" on notifications for update using (user_id=auth.uid());

-- D. TRIGGERS: audit trail, notifications and waiting-list promotion happen inside the database
create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.profiles(id,name) values (new.id, coalesce(new.raw_user_meta_data->>'name', new.email)); return new; end $$;
create trigger on_signup after insert on auth.users for each row execute function handle_new_user();

create function audit_row() returns trigger language plpgsql security definer as $$
declare j jsonb := to_jsonb(new);
begin insert into audit_log(actor,action,detail,booking_id,resource_id) values (auth.uid(),
  initcap(tg_table_name)||' '||lower(tg_op)||coalesce(': '||(j->>'status'),''), coalesce(j->>'reason',j->>'description',j->>'name',''),
  case when tg_table_name='bookings' then (j->>'id')::uuid else (j->>'booking_id')::uuid end,
  case when tg_table_name='resources' then (j->>'id')::uuid else (j->>'resource_id')::uuid end);
return new; end $$;
create trigger a_bookings after insert or update on bookings for each row execute function audit_row();
create trigger a_incidents after insert or update on incidents for each row execute function audit_row();
create trigger a_credentials after insert or update on credentials for each row execute function audit_row();
create trigger a_resources after insert or update on resources for each row execute function audit_row();

create function notify_booking() returns trigger language plpgsql security definer as $$
declare rn text; begin select name into rn from resources where id=new.resource_id;
 if tg_op='INSERT' then insert into notifications(user_id,msg)
   select uid,'New request for '||rn from (select owner_id uid from resources where id=new.resource_id union select user_id from resource_managers where resource_id=new.resource_id) q;
 elsif new.status is distinct from old.status then insert into notifications(user_id,msg) values (new.user_id, rn||': '||new.status||coalesce('. '||new.reason,'')); end if;
return new; end $$;
create trigger n_booking after insert or update on bookings for each row execute function notify_booking();

create function promote_waitlist() returns trigger language plpgsql security definer as $$
begin if old.status='approved' and new.status='cancelled' then
  update bookings set status='pending', reason='Slot freed. You had the highest priority score among waiting requests. Awaiting owner review.'
  where id=(select w.id from bookings w where w.resource_id=new.resource_id and w.status='waitlisted' and w.slot && new.slot order by w.score desc limit 1);
end if; return new; end $$;
create trigger p_waitlist after update on bookings for each row execute function promote_waitlist();

-- E. After creating 4 users in Authentication > Users (student/owner/manager/admin @lendbench.test), run:
-- update profiles set role='owner',verified=true,name='Dr. Mehta' where id=(select id from auth.users where email='owner@lendbench.test');
-- update profiles set role='manager',verified=true,name='Kiran Das' where id=(select id from auth.users where email='manager@lendbench.test');
-- update profiles set role='admin',verified=true,name='Priya Nair' where id=(select id from auth.users where email='admin@lendbench.test');
-- update profiles set name='Asha Rao',need=true where id=(select id from auth.users where email='student@lendbench.test');
-- Then seed resources:
-- insert into resources(owner_id,name,category,location,requires,max_hrs,monthly_cap,deposit,supervised,rules)
-- select (select id from profiles where role='owner' limit 1), v.* from (values
--  ('Prusa MK4 3D printer','Fabrication','Block C, room 104','{"3D Printer Safety"}'::text[],4,8,0,true,'Staff present for first print. PLA only.'),
--  ('Keysight oscilloscope bench','Electronics','Block B, lab 2','{"Electronics Lab Induction"}'::text[],3,6,0,false,'No mains devices above 50 V.'),
--  ('Seminar room B2','Spaces','Block B, floor 2','{}'::text[],3,10,0,false,'Seats 20. Leave chairs in rows.'),
--  ('Mirrorless camera kit','Media','Media Cell','{}'::text[],8,16,2000,false,'Rs 2000 refundable deposit. Return all parts.')) v;
-- insert into resource_managers select r.id,p.id from resources r, profiles p where p.role='manager';

-- F. TABLE PERMISSIONS (needed on some projects; RLS still decides which rows each person can touch)
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant usage, select on all sequences in schema public to authenticated;
grant select on busy_slots to authenticated;
revoke insert, update, delete on audit_log from authenticated;  -- audit history stays tamper-proof
alter default privileges in schema public grant select, insert, update, delete on tables to authenticated;
