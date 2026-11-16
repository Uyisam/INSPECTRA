
import { useState, type FormEvent } from "react";
import { createAsset } from "./api";

type Project = {
  id: number;
  name: string;
};

type Asset = {
  id: number;
  name: string;
  asset_type: string;
  target: string;
  project_id: number;
};

type Props = {
  projects: Project[];
  assets: Asset[];
  onRefresh: () => Promise<void>;
};

export default function Assets({ projects, assets, onRefresh }: Props) {
  const [name, setName] = useState("");
  const [assetType, setAssetType] = useState("filesystem");
  const [target, setTarget] = useState("");
  const [projectId, setProjectId] = useState("");
  const [criticality, setCriticality] = useState("medium");
  const [environment, setEnvironment] = useState("development");
  const [internetExposed, setInternetExposed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (!name.trim() || !target.trim() || !projectId) {
      setError("Please complete all required fields.");
      return;
    }

    try {
      setSaving(true);

      await createAsset({
        name: name.trim(),
        asset_type: assetType,
        target: target.trim(),
        project_id: Number(projectId),
        criticality,
        environment,
        internet_exposed: internetExposed,
      });

      setName("");
      setTarget("");
      setProjectId("");
      setCriticality("medium");
      setEnvironment("development");
      setInternetExposed(false);

      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not register asset.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="dashboard-page">
      <div className="page-header">
        <div>
          <p className="panel-label">ASSET MANAGEMENT</p>
          <h3>Security Assets</h3>
          <p className="subtitle">
            Register and manage the software assets monitored by Inspectra.
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h4>Register New Asset</h4>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          <label>Asset Name</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Backend Application"
            required
          />

          <label>Asset Type</label>
          <select value={assetType} onChange={(e) => setAssetType(e.target.value)}>
            <option value="filesystem">Filesystem</option>
            <option value="git">Git Repository</option>
          </select>

          <label>Target Path or Repository URL</label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Local path or HTTPS Git repository URL"
            required
          />

          <label>Project</label>
          <select
            value={projectId}
            onChange={(e) => setProjectId(e.target.value)}
            required
          >
            <option value="">Select a project</option>
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>

          <label>Criticality</label>
          <select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>

          <label>Environment</label>
          <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="development">Development</option>
            <option value="testing">Testing</option>
            <option value="staging">Staging</option>
            <option value="production">Production</option>
          </select>

          <label>
            <input
              type="checkbox"
              checked={internetExposed}
              onChange={(e) => setInternetExposed(e.target.checked)}
            />
            Internet exposed
          </label>

          {error && <p role="alert">{error}</p>}

          <button
            className="primary-button"
            disabled={saving || projects.length === 0}
          >
            {saving ? "Registering..." : "Register Asset"}
          </button>

          {projects.length === 0 && (
            <p>Create a project before registering an asset.</p>
          )}
        </form>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h4>Registered Assets</h4>
          <span>{assets.length} assets</span>
        </div>

        {assets.length === 0 ? (
          <div className="empty-state">No assets registered yet.</div>
        ) : (
          <div className="asset-list">
            {assets.map((asset) => (
              <div className="asset-row" key={asset.id}>
                <div>
                  <strong>{asset.name}</strong>
                  <span>{asset.target}</span>
                </div>
                <span className="asset-type">{asset.asset_type}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
