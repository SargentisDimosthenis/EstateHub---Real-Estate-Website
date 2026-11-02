-- EstateHub for Supabase: tables, Row Level Security, storage. Paste into SQL Editor and press Run.
create table profiles(id uuid primary key references auth.users on delete cascade,name text not null,email text,phone text,role text not null default 'client' check(role in('admin','owner','client')),active boolean not null default true,created_at timestamptz default now());
create table properties(id bigint generated always as identity primary key,owner_id uuid not null references profiles on delete cascade,title text not null check(length(title)>=5),descr text not null,tx text not null check(tx in('sale','rent')),ptype text not null check(ptype in('apartment','house','maisonette','land','commercial','other')),price numeric(12,2) not null check(price>0),loc text not null,addr text not null,sqm int not null check(sqm>0),bed int default 0,bath int default 0,floor_no int,yr int,energy text,status text not null default 'pending' check(status in('pending','approved','rejected')),reason text,imgs text[] default '{}',created_at timestamptz default now());
create table conversations(id bigint generated always as identity primary key,pid bigint not null references properties on delete cascade,client_id uuid not null references profiles on delete cascade,owner_id uuid not null references profiles on delete cascade,subj text not null,updated_at timestamptz default now(),unique(pid,client_id));
create table messages(id bigint generated always as identity primary key,cid bigint not null references conversations on delete cascade,sender_id uuid not null references profiles on delete cascade,body text not null,is_read boolean not null default false,created_at timestamptz default now());
create table contacts(id bigint generated always as identity primary key,name text not null,email text not null,phone text,subj text not null,body text not null,status text not null default 'new' check(status in('new','in_progress','resolved')),created_at timestamptz default now());
create table logs(id bigint generated always as identity primary key,admin_id uuid references profiles on delete set null,action text not null,descr text,created_at timestamptz default now());

create function is_admin() returns boolean language sql security definer stable set search_path=public as $$select exists(select 1 from profiles where id=auth.uid() and role='admin' and active)$$;
create function is_active_user(u uuid) returns boolean language sql security definer stable set search_path=public as $$select exists(select 1 from profiles where id=u and active)$$;
create function in_conv(c bigint) returns boolean language sql security definer stable set search_path=public as $$select exists(select 1 from conversations where id=c and (client_id=auth.uid() or owner_id=auth.uid()))$$;

-- profile is created automatically; the role can only be owner or client (never admin)
create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into profiles(id,name,email,phone,role) values(new.id,coalesce(new.raw_user_meta_data->>'name','User'),new.email,new.raw_user_meta_data->>'phone',case when new.raw_user_meta_data->>'role'='owner' then 'owner' else 'client' end);return new;end$$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

-- names (no emails/phones) for listings and conversations; client names are hidden from anonymous visitors
create view pub_profiles as select id,name,role,active,created_at from profiles where role<>'client' or auth.uid() is not null;
grant select on pub_profiles to anon,authenticated;

alter table profiles enable row level security;alter table properties enable row level security;alter table conversations enable row level security;alter table messages enable row level security;alter table contacts enable row level security;alter table logs enable row level security;

create policy p_sel on profiles for select using(id=auth.uid() or is_admin());
create policy p_upd on profiles for update using(is_admin());
create policy p_del on profiles for delete using(is_admin());

create policy pr_sel on properties for select using(owner_id=auth.uid() or is_admin() or (status='approved' and is_active_user(owner_id)));
create policy pr_ins on properties for insert with check(owner_id=auth.uid() and status='pending' and exists(select 1 from profiles where id=auth.uid() and role='owner' and active));
create policy pr_upd on properties for update using(owner_id=auth.uid() or is_admin()) with check(is_admin() or (owner_id=auth.uid() and status='pending'));
create policy pr_del on properties for delete using(owner_id=auth.uid() or is_admin());

create policy c_sel on conversations for select using(client_id=auth.uid() or owner_id=auth.uid());
create policy c_ins on conversations for insert with check(client_id=auth.uid() and owner_id<>auth.uid() and owner_id=(select p.owner_id from properties p where p.id=pid and p.status='approved'));
create policy c_upd on conversations for update using(client_id=auth.uid() or owner_id=auth.uid());

create policy m_sel on messages for select using(in_conv(cid));
create policy m_ins on messages for insert with check(sender_id=auth.uid() and in_conv(cid));
create policy m_upd on messages for update using(in_conv(cid) and sender_id<>auth.uid());

create policy ct_ins on contacts for insert to anon,authenticated with check(status='new');
create policy ct_sel on contacts for select using(is_admin());
create policy ct_upd on contacts for update using(is_admin());
create policy ct_del on contacts for delete using(is_admin());

create policy l_sel on logs for select using(is_admin());
create policy l_ins on logs for insert with check(is_admin() and admin_id=auth.uid());

insert into storage.buckets(id,name,public) values('property-images','property-images',true) on conflict do nothing;
create policy img_ins on storage.objects for insert to authenticated with check(bucket_id='property-images' and (storage.foldername(name))[1]=auth.uid()::text);
create policy img_del on storage.objects for delete to authenticated using(bucket_id='property-images' and ((storage.foldername(name))[1]=auth.uid()::text or is_admin()));

-- AFTER you register your own account in the app, make it the administrator (replace the email):
-- update profiles set role='admin' where email='YOUR_EMAIL';
