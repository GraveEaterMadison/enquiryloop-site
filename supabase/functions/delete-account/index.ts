import { createClient } from "npm:@supabase/supabase-js@2";

const allowedOrigin = "https://graveeatermadison.github.io";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.headers.get("origin") !== allowedOrigin) return response({ error: "Origin not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return response({ error: "Method not allowed." }, 405);

  try {
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    if (!token) return response({ error: "Sign in again before deleting your account." }, 401);

    const url = Deno.env.get("SUPABASE_URL");
    const publishableKeys = JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS") || "{}");
    const secretKeys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") || "{}");
    const publishableKey = publishableKeys.default;
    const secretKey = secretKeys.default;
    if (!url || !publishableKey || !secretKey) {
      return response({ error: "Account deletion is temporarily unavailable. Contact support." }, 503);
    }

    const userClient = createClient(url, publishableKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: authHeader } },
    });
    const { data: userData, error: userError } = await userClient.auth.getUser(token);
    if (userError || !userData.user) return response({ error: "Your session is invalid or expired. Sign in again." }, 401);
    const user = userData.user;

    let body: { confirmation?: string };
    try { body = await req.json(); } catch { return response({ error: "Invalid request." }, 400); }
    if (body.confirmation !== "DELETE") return response({ error: "Explicit DELETE confirmation is required." }, 400);

    const admin = createClient(url, secretKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: memberships, error: memberError } = await admin
      .from("workspace_members").select("workspace_id, role").eq("user_id", user.id);
    if (memberError) throw memberError;
    const workspaceIds = (memberships || []).map((m) => m.workspace_id);
    if (memberships?.some((m) => m.role !== "owner")) {
      return response({ error: "This account is a member of another workspace. Ask that workspace owner to remove your access first." }, 409);
    }

    if (workspaceIds.length) {
      const { data: allMembers, error: allMembersError } = await admin
        .from("workspace_members").select("workspace_id, user_id").in("workspace_id", workspaceIds);
      if (allMembersError) throw allMembersError;
      if ((allMembers || []).some((m) => m.user_id !== user.id)) {
        return response({ error: "A workspace has other members. Transfer ownership or remove those members before deleting this account." }, 409);
      }
    }

    const { error: deleteError } = await admin.auth.admin.deleteUser(user.id);
    if (deleteError) throw deleteError;
    return response({ success: true });
  } catch (_error) {
    return response({ error: "Account deletion failed. No success was reported; contact support if this persists." }, 500);
  }
});
