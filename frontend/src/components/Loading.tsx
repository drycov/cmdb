/**
 * Frontend module for components Loading.
 */
interface LoadingProps {
  label?: string;
}

function Loading({ label = "Загрузка…" }: LoadingProps) {
  return (
    <div className="loading">
      <span className="spinner" />
      <span>{label}</span>
    </div>
  );
}

export default Loading;
/**
 * Lightweight loading state used while lazy routes and async data are resolving.
 */
