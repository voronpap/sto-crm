-- ============================================================
-- AutoMaster CRM / AutoShop
-- FULL DATABASE SCHEMA + LOGIC
-- Compatible with Supabase (PostgreSQL)
-- Run as a single file in Supabase SQL Editor
-- Re-runnable (idempotent where practical)
-- ============================================================

------------------------------
-- 0. Extensions
------------------------------
create extension if not exists pgcrypto;

------------------------------
-- 1. ENUM TYPES (Postgres-safe)
-- NOTE: Postgres doesn't support `create type if not exists`
------------------------------
DO $$ BEGIN
  CREATE TYPE public.autoblock_mode AS ENUM ('on_close','30s','1m','5m','never');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.invoice_status AS ENUM ('estimate','final','paid','canceled');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.discount_type AS ENUM ('none','percent','amount');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.appointment_status AS ENUM ('scheduled','arrived','in_work','done','no_show','canceled');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.day_work_status AS ENUM ('workday','day_off');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Multi-workshop roles
DO $$ BEGIN
  CREATE TYPE public.member_role AS ENUM ('owner','admin','staff','viewer');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Reminders flow
DO $$ BEGIN
  CREATE TYPE public.reminder_status AS ENUM ('open','done','snoozed','canceled');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

------------------------------
-- 2. Helper functions
------------------------------
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.force_user_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  NEW.user_id := auth.uid();
  RETURN NEW;
END;
$$;


------------------------------
-- 3. MULTI-WORKSHOP (TENANCY)
------------------------------

-- WORKSHOPS ("майстерні")
CREATE TABLE IF NOT EXISTS public.workshops (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  timezone text NOT NULL DEFAULT 'Europe/Kyiv',
  phone text,
  address text,
  note text,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_workshops_updated ON public.workshops;
CREATE TRIGGER trg_workshops_updated
BEFORE UPDATE ON public.workshops
FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- WORKSHOP MEMBERS
CREATE TABLE IF NOT EXISTS public.workshop_members (
  workshop_id uuid REFERENCES public.workshops(id) ON DELETE CASCADE,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.member_role NOT NULL DEFAULT 'staff',
  is_active boolean NOT NULL DEFAULT true,
  invited_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  PRIMARY KEY (workshop_id, user_id)
);

DROP TRIGGER IF EXISTS trg_workshop_members_updated ON public.workshop_members;
CREATE TRIGGER trg_workshop_members_updated
BEFORE UPDATE ON public.workshop_members
FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- INIT RPC: create default workshop + membership + settings/security rows
-- (call once after signup from client app)
DROP FUNCTION IF EXISTS public.init_user_workspace(text);
CREATE OR REPLACE FUNCTION public.init_user_workspace(p_workshop_name text DEFAULT 'Моя майстерня')
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
  v_w uuid;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  -- create workshop
  INSERT INTO public.workshops(name, created_by)
  VALUES (COALESCE(NULLIF(p_workshop_name,''),'Моя майстерня'), auth.uid())
  RETURNING id INTO v_w;

  -- add membership as owner
  INSERT INTO public.workshop_members(workshop_id, user_id, role, invited_by)
  VALUES (v_w, auth.uid(), 'owner', auth.uid())
  ON CONFLICT (workshop_id, user_id) DO UPDATE
    SET role = EXCLUDED.role,
        is_active = true,
        updated_at = now();

  -- ensure settings row exists
  INSERT INTO public.user_settings(user_id)
  VALUES (auth.uid())
  ON CONFLICT (user_id) DO NOTHING;

  -- ensure security row exists
  INSERT INTO public.user_security(user_id)
  VALUES (auth.uid())
  ON CONFLICT (user_id) DO NOTHING;

  -- set default workshop id
  UPDATE public.user_settings
  SET default_workshop_id = v_w,
      updated_at = now()
  WHERE user_id = auth.uid();

  RETURN v_w;
END;
$$;

-- ===== ROLE MANAGEMENT RPC (HARD CHECKS) =====
-- We enforce role changes ONLY via RPC (not direct table writes).

-- Helper: get a member role (for UI), defaults to current user
DROP FUNCTION IF EXISTS public.get_member_role(uuid, uuid);
CREATE OR REPLACE FUNCTION public.get_member_role(
  p_workshop_id uuid,
  p_user_id uuid DEFAULT auth.uid()
) RETURNS public.member_role
LANGUAGE sql
STABLE
AS $$
  SELECT wm.role
  FROM public.workshop_members wm
  WHERE wm.workshop_id = p_workshop_id
    AND wm.user_id = p_user_id
    AND wm.is_active = true;
$$;

-- Change member role with strict permissions.
-- Rules:
-- 1) Only members can act.
-- 2) admin can change roles of non-owners, but cannot assign 'owner'.
-- 3) owner can change any role, BUT cannot remove the last remaining owner.
-- 4) Nobody can promote themselves to owner.
DROP FUNCTION IF EXISTS public.change_member_role(uuid, uuid, public.member_role);
CREATE OR REPLACE FUNCTION public.change_member_role(
  p_workshop_id uuid,
  p_target_user_id uuid,
  p_new_role public.member_role
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_actor_id uuid;
  v_actor_role public.member_role;
  v_target_role public.member_role;
  v_owner_count int;
BEGIN
  v_actor_id := auth.uid();
  IF v_actor_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT wm.role INTO v_actor_role
  FROM public.workshop_members wm
  WHERE wm.workshop_id = p_workshop_id
    AND wm.user_id = v_actor_id
    AND wm.is_active = true;

  IF v_actor_role IS NULL THEN
    RAISE EXCEPTION 'Access denied (not a member)';
  END IF;

  SELECT wm.role INTO v_target_role
  FROM public.workshop_members wm
  WHERE wm.workshop_id = p_workshop_id
    AND wm.user_id = p_target_user_id
    AND wm.is_active = true;

  IF v_target_role IS NULL THEN
    RAISE EXCEPTION 'Target not found (not an active member)';
  END IF;

  -- disallow self-promotion to owner
  IF p_target_user_id = v_actor_id AND p_new_role = 'owner' THEN
    RAISE EXCEPTION 'Cannot promote yourself to owner';
  END IF;

  -- admin restrictions
  IF v_actor_role = 'admin' THEN
    IF p_new_role = 'owner' THEN
      RAISE EXCEPTION 'Admin cannot assign owner role';
    END IF;
    IF v_target_role = 'owner' THEN
      RAISE EXCEPTION 'Admin cannot change owner role';
    END IF;
    -- admin can change staff/viewer/admin
    UPDATE public.workshop_members
    SET role = p_new_role,
        updated_at = now()
    WHERE workshop_id = p_workshop_id
      AND user_id = p_target_user_id;

    RETURN TRUE;
  END IF;

  -- owner powers + last-owner protection
  IF v_actor_role = 'owner' THEN
    IF v_target_role = 'owner' AND p_new_role <> 'owner' THEN
      SELECT count(*) INTO v_owner_count
      FROM public.workshop_members
      WHERE workshop_id = p_workshop_id
        AND is_active = true
        AND role = 'owner';

      IF v_owner_count <= 1 THEN
        RAISE EXCEPTION 'Cannot remove the last owner of a workshop';
      END IF;
    END IF;

    UPDATE public.workshop_members
    SET role = p_new_role,
        updated_at = now()
    WHERE workshop_id = p_workshop_id
      AND user_id = p_target_user_id;

    RETURN TRUE;
  END IF;

  -- staff/viewer cannot change roles
  RAISE EXCEPTION 'Access denied (insufficient role)';
END;
$$;

-- Optional: deactivate a member (owner/admin only), with last-owner protection
DROP FUNCTION IF EXISTS public.deactivate_member(uuid, uuid);
CREATE OR REPLACE FUNCTION public.deactivate_member(
  p_workshop_id uuid,
  p_target_user_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_actor_id uuid;
  v_actor_role public.member_role;
  v_target_role public.member_role;
  v_owner_count int;
BEGIN
  v_actor_id := auth.uid();
  IF v_actor_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT role INTO v_actor_role
  FROM public.workshop_members
  WHERE workshop_id = p_workshop_id
    AND user_id = v_actor_id
    AND is_active = true;

  IF v_actor_role IS NULL THEN
    RAISE EXCEPTION 'Access denied (not a member)';
  END IF;

  IF v_actor_role NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'Access denied (insufficient role)';
  END IF;

  SELECT role INTO v_target_role
  FROM public.workshop_members
  WHERE workshop_id = p_workshop_id
    AND user_id = p_target_user_id
    AND is_active = true;

  IF v_target_role IS NULL THEN
    RAISE EXCEPTION 'Target not found (not an active member)';
  END IF;

  -- admin cannot deactivate owner
  IF v_actor_role = 'admin' AND v_target_role = 'owner' THEN
    RAISE EXCEPTION 'Admin cannot deactivate an owner';
  END IF;

  -- cannot deactivate last owner
  IF v_target_role = 'owner' THEN
    SELECT count(*) INTO v_owner_count
    FROM public.workshop_members
    WHERE workshop_id = p_workshop_id
      AND is_active = true
      AND role = 'owner';

    IF v_owner_count <= 1 THEN
      RAISE EXCEPTION 'Cannot deactivate the last owner of a workshop';
    END IF;
  END IF;

  UPDATE public.workshop_members
  SET is_active = false,
      updated_at = now()
  WHERE workshop_id = p_workshop_id
    AND user_id = p_target_user_id;

  RETURN TRUE;
END;
$$;

-- ===== INVITES =====

-- Invitations table (pending invites)
CREATE TABLE IF NOT EXISTS public.workshop_invites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workshop_id uuid REFERENCES public.workshops(id) ON DELETE CASCADE,
  email text NOT NULL,
  role public.member_role NOT NULL DEFAULT 'staff',
  token uuid NOT NULL DEFAULT gen_random_uuid(),
  status text NOT NULL DEFAULT 'pending', -- pending | accepted | revoked | expired
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '14 days'),
  invited_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE (workshop_id, email, status)
);

CREATE INDEX IF NOT EXISTS ix_workshop_invites_token
ON public.workshop_invites(token);

DROP TRIGGER IF EXISTS trg_workshop_invites_updated ON public.workshop_invites;
CREATE TRIGGER trg_workshop_invites_updated
BEFORE UPDATE ON public.workshop_invites
FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Invite by email (owner/admin). Returns invite token.
DROP FUNCTION IF EXISTS public.invite_member(uuid, text, public.member_role);
CREATE OR REPLACE FUNCTION public.invite_member(
  p_workshop_id uuid,
  p_email text,
  p_role public.member_role DEFAULT 'staff'
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_actor_id uuid;
  v_actor_role public.member_role;
  v_token uuid;
BEGIN
  v_actor_id := auth.uid();
  IF v_actor_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT role INTO v_actor_role
  FROM public.workshop_members
  WHERE workshop_id = p_workshop_id
    AND user_id = v_actor_id
    AND is_active = true;

  IF v_actor_role IS NULL THEN
    RAISE EXCEPTION 'Access denied (not a member)';
  END IF;

  IF v_actor_role NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'Access denied (insufficient role)';
  END IF;

  -- admin cannot invite owners
  IF v_actor_role = 'admin' AND p_role = 'owner' THEN
    RAISE EXCEPTION 'Admin cannot invite owner';
  END IF;

  IF p_email IS NULL OR btrim(p_email) = '' THEN
    RAISE EXCEPTION 'Email is required';
  END IF;

  INSERT INTO public.workshop_invites(workshop_id, email, role, invited_by)
  VALUES (p_workshop_id, lower(btrim(p_email)), p_role, v_actor_id)
  RETURNING token INTO v_token;

  RETURN v_token;
END;
$$;

-- Accept invite for current user by token
-- Adds (workshop_id, auth.uid()) as member with invite role
DROP FUNCTION IF EXISTS public.accept_invite(uuid);
CREATE OR REPLACE FUNCTION public.accept_invite(p_token uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_uid uuid;
  v_inv public.workshop_invites%ROWTYPE;
BEGIN
  v_uid := auth.uid();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT * INTO v_inv
  FROM public.workshop_invites
  WHERE token = p_token
    AND status = 'pending'
    AND expires_at > now();

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invite not found or expired';
  END IF;

  INSERT INTO public.workshop_members(workshop_id, user_id, role, invited_by)
  VALUES (v_inv.workshop_id, v_uid, v_inv.role, v_inv.invited_by)
  ON CONFLICT (workshop_id, user_id) DO UPDATE
    SET role = EXCLUDED.role,
        is_active = true,
        updated_at = now();

  UPDATE public.workshop_invites
  SET status = 'accepted',
      updated_at = now()
  WHERE id = v_inv.id;

  -- if user has no default workshop, set it
  INSERT INTO public.user_settings(user_id)
  VALUES (v_uid)
  ON CONFLICT (user_id) DO NOTHING;

  UPDATE public.user_settings
  SET default_workshop_id = COALESCE(default_workshop_id, v_inv.workshop_id),
      updated_at = now()
  WHERE user_id = v_uid;

  RETURN v_inv.workshop_id;
END;
$$;

-- Revoke invite (owner/admin). Marks as revoked.
DROP FUNCTION IF EXISTS public.revoke_invite(uuid, uuid);
CREATE OR REPLACE FUNCTION public.revoke_invite(
  p_workshop_id uuid,
  p_token uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_actor_id uuid;
  v_actor_role public.member_role;
BEGIN
  v_actor_id := auth.uid();
  IF v_actor_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT role INTO v_actor_role
  FROM public.workshop_members
  WHERE workshop_id = p_workshop_id
    AND user_id = v_actor_id
    AND is_active = true;

  IF v_actor_role IS NULL THEN
    RAISE EXCEPTION 'Access denied (not a member)';
  END IF;

  IF v_actor_role NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'Access denied (insufficient role)';
  END IF;

  UPDATE public.workshop_invites
  SET status = 'revoked',
      updated_at = now()
  WHERE workshop_id = p_workshop_id
    AND token = p_token
    AND status = 'pending';

  RETURN FOUND;
END;
$$;
