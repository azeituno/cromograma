-- PCTD (planejamento docente) · rode no SQL Editor do Supabase (pode rodar de novo sem problema)
create table if not exists pctd (tid text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz default now());
create table if not exists pctd_keys (tid text primary key, token text not null);
create table if not exists pctd_docentes (email text primary key, nome text);
alter table pctd enable row level security;
alter table pctd_keys enable row level security;
alter table pctd_docentes enable row level security;

-- docente cadastrado pela coordenação (entra com e-mail e senha e edita só o PCTD)
create or replace function is_docente() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from pctd_docentes where lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));
$$;

drop policy if exists pctd_ler on pctd;
create policy pctd_ler on pctd for select to anon, authenticated using (true);
drop policy if exists pctd_admin on pctd;
create policy pctd_admin on pctd for all to authenticated using (is_admin()) with check (is_admin());
drop policy if exists pctdk_admin on pctd_keys;
create policy pctdk_admin on pctd_keys for all to authenticated using (is_admin()) with check (is_admin());
drop policy if exists pd_admin on pctd_docentes;
create policy pd_admin on pctd_docentes for all to authenticated using (is_admin()) with check (is_admin());
drop policy if exists pd_self on pctd_docentes;
create policy pd_self on pctd_docentes for select to authenticated using (lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));

grant usage on schema public to anon, authenticated;
grant select on pctd to anon, authenticated;
grant select, insert, update, delete on pctd, pctd_keys, pctd_docentes to authenticated;
grant execute on function is_admin() to anon, authenticated;
grant execute on function is_docente() to anon, authenticated;

-- grava um campo do PCTD: administrador ou docente cadastrado
create or replace function pctd_set(p_tid text, p_token text, p_key text, p_val jsonb) returns timestamptz
language plpgsql security definer set search_path = public as $$
declare t timestamptz;
begin
  if not (is_admin() or is_docente() or exists (select 1 from pctd_keys where tid = p_tid and token = p_token and length(p_token) >= 16)) then
    raise exception 'sem permissão para editar este PCTD';
  end if;
  if length(p_key) > 80 or pg_column_size(p_val) > 60000 then raise exception 'conteúdo grande demais'; end if;
  insert into pctd (tid, data) values (p_tid, case when p_val is null or p_val = 'null'::jsonb then '{}'::jsonb else jsonb_build_object(p_key, p_val) end)
  on conflict (tid) do update set
    data = case when p_val is null or p_val = 'null'::jsonb then pctd.data - p_key else pctd.data || jsonb_build_object(p_key, p_val) end,
    updated_at = now()
  returning updated_at into t;
  return t;
end $$;
revoke all on function pctd_set(text, text, text, jsonb) from public;
grant execute on function pctd_set(text, text, text, jsonb) to anon, authenticated;
