import { Router } from "express";
import { supabaseAdmin } from "@workspace/db";

const router = Router();

// Sync admin roles - called once on setup to fix admin users
router.post("/sync-roles", async (req, res) => {
  try {
    const { data: adminUsers } = await supabaseAdmin
      .from("admin_users")
      .select("email, role");

    if (!adminUsers) return res.json({ synced: 0 });

    const { data: authListData } = await supabaseAdmin.auth.admin.listUsers();
    const authUsers = authListData?.users ?? [];

    let synced = 0;
    for (const au of adminUsers) {
      if (au.role?.toLowerCase() !== "admin") continue;
      const authUser = authUsers.find(
        (u) => u.email?.toLowerCase() === au.email?.toLowerCase()
      );
      if (!authUser) continue;

      await supabaseAdmin
        .from("user_roles")
        .upsert({ user_id: authUser.id, role: "admin" }, { onConflict: "user_id" });
      synced++;
    }

    res.json({ synced, message: `Synced ${synced} admin(s)` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
