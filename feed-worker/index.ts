interface Env {
  SYNC_SECRET?: string;
}

const SYNC_ENDPOINT = "https://scam-detector-a92.pages.dev/api/internal/feed-sync";

export default {
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil((async () => {
      if (!env.SYNC_SECRET) {
        console.error("PHISHUNT_SYNC_SECRET_NOT_CONFIGURED");
        return;
      }

      try {
        const response = await fetch(SYNC_ENDPOINT, {
          method: "POST",
          headers: {
            "authorization": "Bearer " + env.SYNC_SECRET,
            "content-type": "application/json",
            "accept": "application/json"
          },
          body: JSON.stringify({ source: "phishunt" }),
          redirect: "follow"
        });
        const body = await response.text();
        console.log(JSON.stringify({
          event: "phishunt_sync",
          status: response.status,
          response: body.slice(0, 800)
        }));

        const monitorResponse = await fetch("https://scam-detector-a92.pages.dev/api/internal/monitor-run", {
          method: "POST",
          headers: {
            "authorization": "Bearer " + env.SYNC_SECRET,
            "content-type": "application/json",
            "accept": "application/json"
          },
          body: JSON.stringify({ source: "scheduled-domain-monitor" }),
          redirect: "manual"
        });
        const monitorBody = await monitorResponse.text();
        console.log(JSON.stringify({
          event: "website_monitor_run",
          status: monitorResponse.status,
          response: monitorBody.slice(0, 800)
        }));
      } catch (error) {
        console.error("PHISHUNT_SYNC_REQUEST_FAILED", error instanceof Error ? error.name : "UnknownError");
      }
    })());
  }
};
