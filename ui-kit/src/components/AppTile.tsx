import { Badge } from "./Badge";
import "./AppTile.css";

export interface CatalogApp {
  id: string;
  displayName: string;
  summary?: string;
  enabled: boolean;
  /** Where it is published, when it is. */
  url?: string;
  /** systemd's view. `unknown` before the first health read. */
  health?: "active" | "failed" | "unknown";
  /**
   * How it is protected. `own-login` means the app authenticates itself
   * (Plex, Jellyfin) and must NOT sit behind forward-auth: their native
   * clients have no browser to complete a redirect with, so they do not
   * get a login prompt, they fail to connect.
   */
  auth?: "sso" | "own-login" | "none";
}

export interface AppTileProps {
  app: CatalogApp;
  onToggle?: (id: string, enabled: boolean) => void;
  onOpenSettings?: (id: string) => void;
}

/**
 * One catalog app, as the dashboard shows it.
 *
 * The dashboard is a window onto the system, not a rendering of the
 * schema — so a tile leads with what the operator wants to know (is it
 * on, is it healthy, where do I click it) and keeps the settings behind a
 * deliberate step. The product's own framing: setup should be
 * self-driving, and the UI is for seeing and correcting it.
 *
 * `auth` is shown because "published" and "protected" are different
 * facts, and an app on a real domain with neither SSO nor a login of its
 * own is the hole the whole forced-SSO rule exists to close.
 */
export function AppTile({ app, onToggle, onOpenSettings }: AppTileProps) {
  return (
    <article className="fk-tile" data-enabled={app.enabled}>
      <div className="fk-tile-head">
        <h3 className="fk-tile-name">{app.displayName}</h3>
        <label className="fk-tile-switch">
          <input
            type="checkbox"
            checked={app.enabled}
            onChange={(e) => onToggle?.(app.id, e.target.checked)}
            aria-label={`Enable ${app.displayName}`}
          />
          <span>{app.enabled ? "Enabled" : "Off"}</span>
        </label>
      </div>

      {app.summary && <p className="fk-tile-summary">{app.summary}</p>}

      {app.enabled && (
        <>
          <div className="fk-tile-badges">
            {app.health === "active" && <Badge tone="ok">Running</Badge>}
            {app.health === "failed" && <Badge tone="accent">Not running</Badge>}
            {app.auth === "sso" && <Badge tone="accent">Behind SSO</Badge>}
            {app.auth === "own-login" && <Badge>Its own login</Badge>}
            {app.auth === "none" && <Badge tone="accent">No authentication</Badge>}
          </div>

          <div className="fk-tile-foot">
            {app.url ? (
              <a className="fk-tile-link" href={`https://${app.url}`} rel="noopener noreferrer">
                {app.url}
              </a>
            ) : (
              <span className="fk-tile-local">reachable only from this machine</span>
            )}
            <button type="button" onClick={() => onOpenSettings?.(app.id)}>
              Settings
            </button>
          </div>
        </>
      )}
    </article>
  );
}
