import "./AppStatusTable.css";

export interface AppStatus {
  name: string;
  url: string;
  /** systemd says the unit is active. */
  service: boolean;
  /** It answered on its own hostname; the string is the observed result. */
  reachable: string | false;
  /**
   * Certificate issuer, or `"self-signed"`.
   *
   * A self-signed certificate is a FAILURE, not a footnote. ferrum falls
   * back to one when an ACME order fails, which is the right safety
   * behaviour — but an apply once reported success while every hostname
   * served `CN=minica root ca`, and the operator had no way to know.
   */
  certificate: string | "self-signed" | false;
}

export interface AppStatusTableProps {
  apps: AppStatus[];
}

/**
 * Per-app truth, in three separate columns.
 *
 * "Running", "answers on its own hostname" and "has a real certificate"
 * are three different claims, and merging them into one tick IS the
 * failure mode this table exists to prevent. A service can be active and
 * unreachable; reachable and serving a certificate a browser will refuse.
 * Each gets its own column so a half-working app cannot render as a
 * working one.
 */
export function AppStatusTable({ apps }: AppStatusTableProps) {
  return (
    <div className="fk-apps-scroll">
      <table className="fk-apps">
        <thead>
          <tr>
            <th>App</th>
            <th>URL</th>
            <th>Service</th>
            <th>Reachable</th>
            <th>Certificate</th>
          </tr>
        </thead>
        <tbody>
          {apps.map((a) => (
            <tr key={a.name}>
              <td className="fk-apps-mono">{a.name}</td>
              <td className="fk-apps-mono">{a.url}</td>
              <td className={a.service ? "fk-yes" : "fk-no"}>{a.service ? "active" : "down"}</td>
              <td className={a.reachable ? "fk-yes" : "fk-no"}>{a.reachable || "no answer"}</td>
              <td className={a.certificate && a.certificate !== "self-signed" ? "fk-yes" : "fk-no"}>
                {a.certificate || "none"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
