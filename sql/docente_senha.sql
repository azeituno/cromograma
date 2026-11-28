-- Senha dos docentes definida pela coordenação (Docentes e escalas) · rode no SQL Editor do Supabase (pode rodar de novo sem problema)
create extension if not exists pgcrypto with schema extensions;
create or replace function docente_senha(p_email text, p_senha text) returns boolean
language plpgsql security definer set search_path = public, auth, extensions as $$
begin
  if not is_admin() then raise exception 'sem permissão'; end if;
  if coalesce(length(p_senha), 0) < 6 then raise exception 'a senha precisa ter pelo menos 6 caracteres'; end if;
  update auth.users
     set encrypted_password = extensions.crypt(p_senha, extensions.gen_salt('bf')),
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at = now()
   where lower(email) = lower(trim(p_email));
  return found;
end $$;
revoke all on function docente_senha(text, text) from public;
grant execute on function docente_senha(text, text) to authenticated;
