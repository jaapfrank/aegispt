import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, Home, RefreshCw, RotateCcw, Target } from 'lucide-react';
import { Link } from 'react-router-dom';

type ErrorBoundaryProps = {
  children: ReactNode;
  resetKey?: string;
};

type ErrorBoundaryState = {
  error: Error | null;
  errorInfo: ErrorInfo | null;
};

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    error: null,
    errorInfo: null,
  };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error, errorInfo: null };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ error, errorInfo });
  }

  componentDidUpdate(previousProps: ErrorBoundaryProps) {
    if (previousProps.resetKey !== this.props.resetKey && this.state.error) {
      this.reset();
    }
  }

  reset = () => {
    this.setState({ error: null, errorInfo: null });
  };

  render() {
    if (!this.state.error) {
      return this.props.children;
    }

    const errorName = this.state.error.name || 'Render error';
    const errorMessage = this.state.error.message || 'A React view failed while rendering.';

    return (
      <section className="flex min-h-full items-center justify-center p-6">
        <div className="crash-recovery-card neon-panel w-full max-w-3xl rounded-lg border border-red/30 p-6 text-center">
          <div className="empty-state-orbit mx-auto mb-5">
            <div className="empty-state-orbit-ring" />
            <div className="empty-state-orbit-core">
              <AlertTriangle size={28} />
            </div>
          </div>
          <p className="text-[0.77rem] font-bold uppercase tracking-[0.24em] text-red">Crash Recovery</p>
          <h1 className="mt-2 text-2xl font-semibold text-text">The view stopped rendering safely.</h1>
          <p className="mx-auto mt-3 max-w-2xl text-[1rem] leading-6 text-muted">
            AegisPT caught the UI fault before it could white-screen the operator console. Runtime tasks,
            approvals, scope, credentials, and kill-switch state were not changed.
          </p>

          <div className="mx-auto mt-5 max-w-2xl rounded-md border border-border bg-bg/45 p-3 text-left">
            <div className="text-[0.77rem] font-bold uppercase tracking-wider text-muted">{errorName}</div>
            <p className="mt-1 break-words font-mono text-[0.925rem] leading-5 text-text">{errorMessage}</p>
            {this.state.errorInfo?.componentStack && (
              <details className="mt-3">
                <summary className="cursor-pointer text-[0.85rem] font-semibold text-cyan">Component stack</summary>
                <pre className="terminal-code mt-2 max-h-[180px] overflow-auto whitespace-pre-wrap rounded-md border p-3 text-[0.85rem] leading-5">
                  {this.state.errorInfo.componentStack.trim()}
                </pre>
              </details>
            )}
          </div>

          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <button
              type="button"
              onClick={this.reset}
              className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan hover:bg-cyan/15"
            >
              <RotateCcw size={15} />
              Try Again
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/40 px-4 py-2 text-[1rem] font-semibold text-muted hover:text-text"
            >
              <RefreshCw size={15} />
              Reload App
            </button>
            <Link
              to="/"
              onClick={this.reset}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/40 px-4 py-2 text-[1rem] font-semibold text-muted hover:text-text"
            >
              <Home size={15} />
              Dashboard
            </Link>
            <Link
              to="/intake"
              onClick={this.reset}
              className="inline-flex items-center gap-2 rounded-md border border-amber/30 bg-amber/10 px-4 py-2 text-[1rem] font-semibold text-amber hover:bg-amber/15"
            >
              <Target size={15} />
              New Mission
            </Link>
          </div>
        </div>
      </section>
    );
  }
}
