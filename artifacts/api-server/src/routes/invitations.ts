import { Router } from "express";
import { supabaseAdmin } from "@workspace/db";

const router = Router();

// Validate an invitation token (public - no auth needed)
router.get("/:token/validate", async (req, res) => {
  const { token } = req.params;
  try {
    const { data, error } = await supabaseAdmin.rpc("validate_invitation_token", {
      token_param: token,
    });
    if (error) throw error;
    res.json(data);
  } catch (err: any) {
    res.status(400).json({ valid: false, error: err.message });
  }
});

// Create an invitation link (admin only)
router.post("/", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = authHeader.slice(7);

  // Verify the user and check admin role
  const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !user) {
    return res.status(401).json({ error: "Invalid token" });
  }

  const { data: roleData } = await supabaseAdmin
    .from("user_roles")
    .select("role")
    .eq("user_id", user.id)
    .maybeSingle();

  if (roleData?.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  const { email } = req.body as { email?: string };

  const { data, error } = await supabaseAdmin
    .from("invitation_links")
    .insert({
      created_by: user.id,
      email: email ?? null,
      max_uses: 1,
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    })
    .select("token, id, email, expires_at")
    .single();

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ token: data.token, id: data.id, email: data.email, expires_at: data.expires_at });
});

// Sync admin roles from admin_users to user_roles (admin bootstrap)
router.post("/sync-admin-roles", async (req, res) => {
  try {
    const { data: adminUsers } = await supabaseAdmin
      .from("admin_users")
      .select("email, role");

    if (!adminUsers) return res.json({ synced: 0 });

    let synced = 0;
    for (const au of adminUsers) {
      if (au.role?.toLowerCase() !== "admin") continue;
      // Find auth user by email
      const { data: authUsers } = await supabaseAdmin.auth.admin.listUsers();
      const authUser = authUsers?.users?.find(
        (u) => u.email?.toLowerCase() === au.email?.toLowerCase()
      );
      if (!authUser) continue;

      await supabaseAdmin
        .from("user_roles")
        .upsert({ user_id: authUser.id, role: "admin" }, { onConflict: "user_id" });
      synced++;
    }

    res.json({ synced });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// List invitations (admin only)
router.get("/", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = authHeader.slice(7);

  const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: "Invalid token" });

  const { data: roleData } = await supabaseAdmin
    .from("user_roles")
    .select("role")
    .eq("user_id", user.id)
    .maybeSingle();

  if (roleData?.role !== "admin") return res.status(403).json({ error: "Admin access required" });

  const { data, error } = await supabaseAdmin
    .from("invitation_links")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

export default router;
