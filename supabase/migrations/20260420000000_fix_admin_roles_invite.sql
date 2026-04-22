-- =============================================
-- Fix Admin Role Sync + Invitation System
-- Compatible with existing app_role enum
-- Run this in Supabase SQL Editor
-- =============================================

-- 0. Ensure app_role enum exists
DO $$ BEGIN
  CREATE TYPE public.app_role AS ENUM ('admin', 'user');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- 1. Ensure user_roles table exists
CREATE TABLE IF NOT EXISTS public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL DEFAULT 'user',
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- 2. Recreate has_role function with proper enum casting
DROP FUNCTION IF EXISTS public.has_role(uuid, text);
DROP FUNCTION IF EXISTS public.has_role(uuid, public.app_role);
DROP FUNCTION IF EXISTS public.has_role(public.app_role, uuid);

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role = _role::public.app_role
  );
$$;

-- 3. Sync admin_users (role='Admin') to user_roles via email match on auth.users
INSERT INTO public.user_roles (user_id, role)
SELECT au.id, 'admin'::public.app_role
FROM auth.users au
JOIN public.admin_users am ON lower(au.email) = lower(am.email)
WHERE lower(am.role) = 'admin'
ON CONFLICT (user_id) DO UPDATE SET role = 'admin'::public.app_role;

-- 4. Ensure invitation_links table exists
CREATE TABLE IF NOT EXISTS public.invitation_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token text NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'hex'),
  email text,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  max_uses integer DEFAULT 1,
  uses_count integer DEFAULT 0,
  expires_at timestamp with time zone DEFAULT (now() + interval '7 days'),
  is_active boolean DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.invitation_links ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Admins can manage invitation links" ON public.invitation_links;
CREATE POLICY "Admins can manage invitation links"
  ON public.invitation_links FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "Service role can manage invitations" ON public.invitation_links;
CREATE POLICY "Service role can manage invitations"
  ON public.invitation_links FOR ALL TO service_role
  USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Public can validate invitation token" ON public.invitation_links;
CREATE POLICY "Public can validate invitation token"
  ON public.invitation_links FOR SELECT TO anon, authenticated
  USING (true);

-- 5. Ensure invitation_usages table exists
CREATE TABLE IF NOT EXISTS public.invitation_usages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  invitation_id uuid NOT NULL REFERENCES public.invitation_links(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  used_at timestamp with time zone NOT NULL DEFAULT now(),
  UNIQUE(invitation_id, user_id)
);

ALTER TABLE public.invitation_usages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Admins can view invitation usages" ON public.invitation_usages;
CREATE POLICY "Admins can view invitation usages"
  ON public.invitation_usages FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "Service role can manage usages" ON public.invitation_usages;
CREATE POLICY "Service role can manage usages"
  ON public.invitation_usages FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- 6. Validate invitation token function
CREATE OR REPLACE FUNCTION public.validate_invitation_token(token_param text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  inv RECORD;
BEGIN
  SELECT * INTO inv
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  IF inv IS NULL THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid or expired invitation link');
  END IF;

  RETURN jsonb_build_object('valid', true, 'invitation_id', inv.id, 'email', inv.email);
END;
$$;

-- 7. Use invitation token function (with proper enum cast)
CREATE OR REPLACE FUNCTION public.use_invitation_token(token_param text, user_id_param uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  inv RECORD;
BEGIN
  SELECT * INTO inv
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  IF inv IS NULL THEN
    RETURN false;
  END IF;

  INSERT INTO public.invitation_usages (invitation_id, user_id)
  VALUES (inv.id, user_id_param)
  ON CONFLICT DO NOTHING;

  UPDATE public.invitation_links
  SET uses_count = uses_count + 1
  WHERE id = inv.id;

  INSERT INTO public.user_roles (user_id, role)
  VALUES (user_id_param, 'user'::public.app_role)
  ON CONFLICT (user_id) DO NOTHING;

  RETURN true;
END;
$$;

-- 8. Trigger for new users
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'user'::public.app_role)
  ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 9. RLS policies on user_roles (NO recursive admin policy here!)
DROP POLICY IF EXISTS "Users can view own role" ON public.user_roles;
CREATE POLICY "Users can view own role"
  ON public.user_roles FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Admins can manage all roles" ON public.user_roles;
DROP POLICY IF EXISTS "Admins can manage roles" ON public.user_roles;

DROP POLICY IF EXISTS "Service role can manage user_roles" ON public.user_roles;
CREATE POLICY "Service role can manage user_roles"
  ON public.user_roles FOR ALL TO service_role
  USING (true) WITH CHECK (true);
