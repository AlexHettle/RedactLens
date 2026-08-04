import type { ReactNode } from 'react'

/** Simple 24×24 stroke icons for the Haven visual system. All decorative —
 * every usage sits next to visible text, so they're hidden from assistive tech. */

interface IconProps {
  size?: number
  strokeWidth?: number
}

function Icon({ size = 15, strokeWidth = 2, children }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  )
}

export function IconLock(props: IconProps) {
  return (
    <Icon strokeWidth={2.4} {...props}>
      <rect x="5" y="11" width="14" height="10" rx="2.2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </Icon>
  )
}

export function IconFolder(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    </Icon>
  )
}

export function IconFile(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M7 3h7l4 4v14a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
      <path d="M14 3v4h4" />
    </Icon>
  )
}

export function IconChevronDown(props: IconProps) {
  return (
    <Icon strokeWidth={2.6} {...props}>
      <path d="M6 9l6 6 6-6" />
    </Icon>
  )
}

export function IconSearch(props: IconProps) {
  return (
    <Icon strokeWidth={2.4} {...props}>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </Icon>
  )
}

export function IconSparkle(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3M6 6l2 2M16 16l2 2M18 6l-2 2M8 16l-2 2" />
      <circle cx="12" cy="12" r="3.2" />
    </Icon>
  )
}

export function IconPerson(props: IconProps) {
  return (
    <Icon strokeWidth={2.2} {...props}>
      <circle cx="12" cy="8" r="3.4" />
      <path d="M5 20c0-3.4 3.1-5.5 7-5.5s7 2.1 7 5.5" />
    </Icon>
  )
}

export function IconCard(props: IconProps) {
  return (
    <Icon strokeWidth={2.2} {...props}>
      <rect x="3" y="6" width="18" height="12" rx="2" />
      <path d="M3 10h18" />
    </Icon>
  )
}

export function IconKey(props: IconProps) {
  return (
    <Icon strokeWidth={2.2} {...props}>
      <rect x="4" y="10" width="16" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </Icon>
  )
}

export function IconRedact(props: IconProps) {
  return (
    <Icon strokeWidth={2.4} {...props}>
      <path d="M4 12h10M4 7h16M4 17h7" />
    </Icon>
  )
}

export function IconExternal(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 15 20 4" />
      <path d="M15 4h5v5" />
      <path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" />
    </Icon>
  )
}

export function IconDownload(props: IconProps) {
  return (
    <Icon strokeWidth={2.2} {...props}>
      <path d="M12 15V3M12 15l-4-4M12 15l4-4M5 19h14" />
    </Icon>
  )
}

export function IconEye(props: IconProps) {
  return (
    <Icon strokeWidth={2.1} {...props}>
      <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6z" />
      <circle cx="12" cy="12" r="2.7" />
    </Icon>
  )
}

export function IconEyeOff(props: IconProps) {
  return (
    <Icon strokeWidth={2.1} {...props}>
      <path d="M3 3l18 18" />
      <path d="M10.6 6.1A10 10 0 0 1 12 6c6 0 9.5 6 9.5 6a15 15 0 0 1-2.3 3" />
      <path d="M6.2 6.2C3.8 8 2.5 12 2.5 12s3.5 6 9.5 6a10 10 0 0 0 3.1-.5" />
    </Icon>
  )
}

export function IconSun(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2.25v2.25M12 19.5v2.25M2.25 12H4.5M19.5 12h2.25M5.1 5.1l1.6 1.6M17.3 17.3l1.6 1.6M18.9 5.1l-1.6 1.6M6.7 17.3l-1.6 1.6" />
    </Icon>
  )
}

export function IconMoon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M20.4 14.6A8.6 8.6 0 0 1 9.4 3.6a8.7 8.7 0 1 0 11 11Z" />
    </Icon>
  )
}

export function IconInfo(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v5M12 16h.01" />
    </Icon>
  )
}

export function IconPencil(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 20h9" />
      <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" />
    </Icon>
  )
}

export function IconShield(props: IconProps) {
  return (
    <Icon strokeWidth={2.2} {...props}>
      <path d="M12 3l7 3v5c0 4.4-3 8.2-7 9-4-.8-7-4.6-7-9V6z" />
    </Icon>
  )
}

export function IconShieldCheck(props: IconProps) {
  return (
    <Icon strokeWidth={2.4} {...props}>
      <path d="M12 3l7 3v5c0 4.4-3 8.2-7 9-4-.8-7-4.6-7-9V6z" />
      <path d="M9 12l2 2 4-4" />
    </Icon>
  )
}

export function IconCheck(props: IconProps) {
  return (
    <Icon strokeWidth={3.4} {...props}>
      <path d="M5 12l4 4 10-10" />
    </Icon>
  )
}
