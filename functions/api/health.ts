export const onRequestGet: PagesFunction = async () => {
  return Response.json(
    { status: "ok", service: "scam-detector-api", platform: "cloudflare-pages" },
    { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } }
  );
};
