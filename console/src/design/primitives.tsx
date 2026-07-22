import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
} from "react";
import type { LucideIcon } from "lucide-react";

type ButtonIntent = "primary" | "secondary" | "danger";
type StatusTone = "neutral" | "success" | "warning" | "danger" | "accent";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  intent?: ButtonIntent;
  icon?: LucideIcon;
  loading?: boolean;
};

export function Button({
  children,
  icon: Icon,
  intent = "secondary",
  loading = false,
  disabled,
  type = "button",
  ...props
}: ButtonProps) {
  return (
    <button
      {...props}
      type={type}
      className="yc-button"
      data-intent={intent}
      data-loading={loading}
      disabled={disabled || loading}
      aria-busy={loading}
    >
      {Icon ? <Icon className="yc-icon" aria-hidden="true" /> : null}
      <span>{children}</span>
    </button>
  );
}

type CardProps = {
  children: ReactNode;
  raised?: boolean;
  className?: string;
};

export function Card({ children, raised = false, className }: CardProps) {
  const classes = className ? `yc-card ${className}` : "yc-card";
  return (
    <section className={classes} data-raised={raised}>
      {children}
    </section>
  );
}

type BadgeProps = {
  children: ReactNode;
  tone?: StatusTone;
  icon?: LucideIcon;
};

export function Badge({ children, tone = "neutral", icon: Icon }: BadgeProps) {
  return (
    <span className="yc-badge" data-tone={tone}>
      {Icon ? <Icon className="yc-icon" aria-hidden="true" /> : null}
      <span>{children}</span>
    </span>
  );
}

type BannerProps = {
  title: string;
  children: ReactNode;
  tone?: Exclude<StatusTone, "neutral" | "success">;
  icon: LucideIcon;
};

export function Banner({ title, children, tone = "accent", icon: Icon }: BannerProps) {
  return (
    <aside className="yc-banner" data-tone={tone} role={tone === "danger" ? "alert" : "status"}>
      <Icon className="yc-icon" aria-hidden="true" />
      <div>
        <h3>{title}</h3>
        <div>{children}</div>
      </div>
    </aside>
  );
}

type FieldProps = {
  id: string;
  label: string;
  help?: string;
  error?: string;
  children: ReactNode;
};

export function Field({ id, label, help, error, children }: FieldProps) {
  return (
    <div className="yc-field">
      <label className="yc-field__label" htmlFor={id}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="yc-field__error" id={`${id}-error`}>
          {error}
        </p>
      ) : help ? (
        <p className="yc-field__help" id={`${id}-help`}>
          {help}
        </p>
      ) : null}
    </div>
  );
}

type TextInputProps = InputHTMLAttributes<HTMLInputElement> & {
  invalid?: boolean;
};

export function TextInput({ invalid = false, ...props }: TextInputProps) {
  const className = props.className ? `yc-input ${props.className}` : "yc-input";
  return <input {...props} className={className} aria-invalid={invalid} />;
}

export function LoadingBlock({ label }: { label: string }) {
  return <div className="yc-skeleton" role="status" aria-label={label} />;
}
