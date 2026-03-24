export default function FirewatchLogo({ size = 18 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M24 2L6 10v14c0 11.1 7.7 21.5 18 24 10.3-2.5 18-12.9 18-24V10L24 2z"
        fill="#0d1117"
        stroke="#00d4aa"
        strokeWidth="2"
      />
      <path
        d="M24 38c-5.5-4-10-9.5-10-16 0-4 2-7 5-9 0 3 1.5 5 3 6 0-5 3-10 6-13 1 3 2 6 2 9 1.5-1.5 2.5-3.5 3-5.5 2 3 3.5 6.5 3.5 10.5 0 7-4.5 13-12.5 18z"
        fill="#00d4aa"
      />
      <path
        d="M24 38c-3.5-3-7-7-7-12 0-3 1.5-5.5 3.5-7 0 2.5 1 4 2 5 0-4 2-7.5 4-10 .7 2 1.3 4 1.3 6.5 1-1 1.7-2.5 2.2-4 1.5 2.5 2.5 5 2.5 8 0 5.5-3.5 10-8.5 13.5z"
        fill="#00ffcc"
        opacity="0.5"
      />
    </svg>
  );
}
