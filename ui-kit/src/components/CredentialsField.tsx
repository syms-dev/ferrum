import { useState } from "react";
import "./CredentialsField.css";

export interface CredentialsFieldProps {
  /** What this login opens, in plain terms. */
  opens?: string;
  minLength?: number;
  onSubmit?: (creds: { username: string; password: string }) => void;
}

/**
 * The admin login the operator chooses, during install.
 *
 * ferrum used to generate this and write it to a root-only file, which
 * the installer's closing report was the only thing that ever showed. On
 * a run that failed before that report, the operator was locked out of
 * their own box with no way to discover the credential short of knowing
 * the file existed. Letting them choose it does not merely improve that;
 * it deletes the failure mode.
 *
 * One pair covers the dashboard and SSO, because two logins for one box
 * is a thing to forget twice.
 *
 * It is collected with the other answers, before the disk is erased, so
 * a failure later in the run never costs the operator their login.
 */
export function CredentialsField({
  opens = "the ferrum dashboard and every app behind single sign-on",
  minLength = 12,
  onSubmit,
}: CredentialsFieldProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");

  const tooShort = password.length > 0 && password.length < minLength;
  const mismatch = confirm.length > 0 && confirm !== password;
  const ready = username.trim().length > 0 && password.length >= minLength && confirm === password;

  return (
    <div className="fk-creds">
      <p className="fk-creds-lede">
        One login opens {opens}. Choose it now — ferrum does not generate one for you, and there
        is nowhere to look it up later.
      </p>

      <div className="fk-creds-field">
        <label htmlFor="fk-creds-user">Username</label>
        <input
          id="fk-creds-user"
          value={username}
          autoComplete="off"
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>

      <div className="fk-creds-field">
        <label htmlFor="fk-creds-pw">Password</label>
        <input
          id="fk-creds-pw"
          type="password"
          value={password}
          autoComplete="new-password"
          aria-describedby="fk-creds-pw-h"
          onChange={(e) => setPassword(e.target.value)}
        />
        <span className="fk-creds-hint" id="fk-creds-pw-h" data-bad={tooShort}>
          {tooShort ? `At least ${minLength} characters.` : `${minLength} characters or more.`}
        </span>
      </div>

      <div className="fk-creds-field">
        <label htmlFor="fk-creds-pw2">Password again</label>
        <input
          id="fk-creds-pw2"
          type="password"
          value={confirm}
          autoComplete="new-password"
          aria-invalid={mismatch || undefined}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {mismatch && (
          <span className="fk-creds-hint" data-bad="true" role="alert">
            These do not match.
          </span>
        )}
      </div>

      <button
        type="button"
        className="fk-creds-go"
        disabled={!ready}
        onClick={() => onSubmit?.({ username, password })}
      >
        Use this login
      </button>
    </div>
  );
}
