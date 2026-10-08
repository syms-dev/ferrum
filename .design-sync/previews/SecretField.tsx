import { SecretField } from "@ferrum/ui-kit";

export const NotSetYet = () => (
  <SecretField
    name="cloudflare-dns-api-token"
    description="Used to answer the DNS-01 challenge and to create the A records for your apps."
    present={false}
  />
);

export const AlreadySet = () => (
  <SecretField
    name="cloudflare-dns-api-token"
    description="Used to answer the DNS-01 challenge and to create the A records for your apps."
    present
  />
);

export const PlexClaim = () => (
  <SecretField
    name="plex-claim-token"
    description="A short-lived token from plex.tv/claim. ferrum claims the server with it, then discards it."
    present={false}
  />
);
