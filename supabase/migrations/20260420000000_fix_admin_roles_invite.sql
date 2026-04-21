-- =============================================
-- Fix Admin Role Sync + Invitation System
-- Run this in Supabase SQL Editor
-- =============================================

-- 1. Ensure user_roles table exists with correct structure
CREATE TABLE IF NOT EXISTS public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'user',
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- 2. Ensure has_role function exists
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  );
$$;

-- 3. Sync admin_users (role='Admin') to user_roles via email match on auth.users
-- This fixes the core bug: admin stored in admin_users but missing from user_roles
INSERT INTO public.user_roles (user_id, role)
SELECT au.id, 'admin'
FROM auth.users au
JOIN public.admin_users am ON lower(au.email) = lower(am.email)
WHERE lower(am.role) = 'admin'
ON CONFLICT (user_id) DO UPDATE SET role = 'admin';

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

-- Allow service role full access
CREATE POLICY "Service role can manage invitations"
  ON public.invitation_links FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

-- Allow anyone to read an invitation by token (for validation on accept page)
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

CREATE POLICY "Service role can manage usages"
  ON public.invitation_usages FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

-- 6. Function to validate invitation token (callable by anyone - used on accept page)
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

-- 7. Function to accept invitation and assign user role (called after registration)
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
  VALUES (user_id_param, 'user')
  ON CONFLICT (user_id) DO NOTHING;

  RETURN true;
END;
$$;

-- 8. Trigger: auto-add any new user signing up directly (not via invite) as 'user'
-- This is a safety net - the invitation flow handles it explicitly
-- But prevents new users from having no role at all
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  -- Only add if not already in user_roles (invitation flow may have already added them)
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'user')
  ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 9. Update RLS policies on user_roles to allow self-read
DROP POLICY IF EXISTS "Users can view own role" ON public.user_roles;
CREATE POLICY "Users can view own role"
  ON public.user_roles FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Admins can manage all roles" ON public.user_roles;
CREATE POLICY "Admins can manage all roles"
  ON public.user_roles FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Service role can manage user_roles"
  ON public.user_roles FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);
