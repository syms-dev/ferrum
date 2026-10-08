import { useState } from "react";
import "./VpnSettings.css";

export interface VpnProvider {
  id: string;
  name: string;
  /** What this provider needs. Differs per provider, which is the whole
   *  reason a preset is not just a dropdown over one credential field. */
  fields: { key: string; label: string; hint?: string; secret?: boolean }[];
  /** Where the operator gets those values, in their provider's own words. */
  where?: string;
}

export interface VpnSettingsProps {
  appName: string;
  providers: VpnProvider[];
  /** The provider in use, or `null` when no VPN is configured. */
  current?: string | null;
  /** True once a config exists. Its contents are never sent back. */
  configured: boolean;
  onSave?: (choice: { provider: string; values: Record<string, string> }) => void;
  onSaveRawConfig?: (conf: string) => void;
  onDisable?: () => void;
}

/**
 * Choosing and changing the VPN qBittorrent tunnels through.
 *
 * Presets exist because the owner asked for the Saltbox shape — pick a
 * provider, type your credentials — and they carry a real cost: providers
 * change endpoints and key formats, and a stale preset produces a config
 * that does not tunnel while the operator believes it does.
 *
 * So two rules are structural here rather than cosmetic. **A raw
 * WireGuard config is always accepted**, for a provider ferrum does not
 * know and for a preset that has broken — a preset is a convenience over
 * that path, never a replacement for it. And **turning the VPN off is an
 * explicit choice that states its consequence**, because for most people
 * running a torrent client it is the wrong answer and must never happen
 * by accident.
 *
 * Existing credentials are never shown. Like every secret in ferrum they
 * are write-only: you replace them, you do not read them back.
 */
export function VpnSettings({
  appName,
  providers,
  current = null,
  configured,
  onSave,
  onSaveRawConfig,
  onDisable,
}: VpnSettingsProps) {
  const [choice, setChoice] = useState<string>(current ?? providers[0]?.id ?? "raw");
  const [values, setValues] = useState<Record<string, string>>({});
  const [raw, setRaw] = useState("");

  const provider = providers.find((p) => p.id === choice);
  const isRaw = choice === "raw";
  const complete = isRaw
    ? raw.trim().length > 0
    : Boolean(provider?.fields.every((f) => (values[f.key] ?? "").trim().length > 0));

  return (
    <section className="fk-vpnset" aria-label={`VPN for ${appName}`}>
      <div className="fk-vpnset-head">
        <h3>How {appName} reaches the internet</h3>
        <span className="fk-vpnset-state" data-on={configured}>
          {configured ? `via ${current ?? "a saved config"}` : "no VPN configured"}
        </span>
      </div>

      <label className="fk-vpnset-label" htmlFor="fk-vpnset-provider">
        Provider
      </label>
      <select
        id="fk-vpnset-provider"
        value={choice}
        onChange={(e) => {
          setChoice(e.target.value);
          setValues({});
        }}
      >
        {providers.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
        <option value="raw">Something else — paste a WireGuard config</option>
      </select>

      {isRaw ? (
        <>
          <label className="fk-vpnset-label" htmlFor="fk-vpnset-raw">
            WireGuard configuration
          </label>
          <textarea
            id="fk-vpnset-raw"
            rows={7}
            spellCheck={false}
            value={raw}
            placeholder={"[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …"}
            onChange={(e) => setRaw(e.target.value)}
          />
          <p className="fk-vpnset-note">
            The file your provider gives you, unchanged. This always works, including when a
            preset above has stopped matching what your provider hands out.
          </p>
        </>
      ) : (
        <>
          {provider?.where && <p className="fk-vpnset-note">{provider.where}</p>}
          {provider?.fields.map((f) => (
            <div key={f.key} className="fk-vpnset-field">
              <label htmlFor={`fk-vpnset-${f.key}`}>{f.label}</label>
              <input
                id={`fk-vpnset-${f.key}`}
                type={f.secret ? "password" : "text"}
                autoComplete="off"
                spellCheck={false}
                value={values[f.key] ?? ""}
                onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
              />
              {f.hint && <span className="fk-vpnset-hint">{f.hint}</span>}
            </div>
          ))}
        </>
      )}

      <div className="fk-vpnset-actions">
        <button
          type="button"
          className="fk-vpnset-save"
          disabled={!complete}
          onClick={() =>
            isRaw ? onSaveRawConfig?.(raw) : onSave?.({ provider: choice, values })
          }
        >
          {configured ? "Replace the VPN config" : "Save and connect"}
        </button>
        {configured && (
          <button type="button" className="fk-vpnset-off" onClick={onDisable}>
            Turn the VPN off
          </button>
        )}
      </div>

      {configured && (
        <p className="fk-vpnset-warn">
          With the VPN off, {appName} reaches trackers from this box&apos;s own address. That is
          almost never what you want.
        </p>
      )}
    </section>
  );
}
