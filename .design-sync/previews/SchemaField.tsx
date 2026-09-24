import { SchemaField } from "@ferrum/ui-kit";

export const TextWithDefault = () => (
  <SchemaField
    name="urlBase"
    schema={{
      type: "string",
      title: "URL base",
      description: "Path prefix to serve under, when the app sits behind a shared hostname.",
      default: "",
    }}
  />
);

export const Toggle = () => (
  <SchemaField
    name="analytics"
    schema={{
      type: "boolean",
      title: "Send anonymous usage data",
      description: "Off unless you turn it on. ferrum never enables this for you.",
      default: false,
    }}
    value={false}
  />
);

export const Choice = () => (
  <SchemaField
    name="logLevel"
    schema={{
      type: "string-enum",
      title: "Log level",
      description: "How much the service writes to the journal.",
      enum: ["trace", "debug", "info", "warn", "error"],
      default: "info",
    }}
    value="debug"
  />
);

export const Number = () => (
  <SchemaField
    name="port"
    schema={{
      type: "integer",
      title: "Port",
      description: "The port the service listens on inside the box.",
      default: 8989,
    }}
  />
);

export const Unsupported = () => (
  <SchemaField
    name="customFormats"
    schema={{
      type: "object",
      title: "Custom formats",
      description: "A nested structure this form cannot safely edit.",
    }}
    unsupported
  />
);
