
import { useState } from "react";
import { createProject } from "./api";

type Project = {
  id: number;
  name: string;
  description?: string | null;
};

type Props = {
  projects: Project[];
  onRefresh: () => Promise<void>;
};

export default function Projects({ projects, onRefresh }: Props) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (!name.trim()) {
      setError("Project name is required.");
      return;
    }

    try {
      setSaving(true);
      await createProject(name.trim(), description.trim());
      setName("");
      setDescription("");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create project.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="dashboard-page">
      <div className="page-header">
        <div>
          <p className="panel-label">PROJECT MANAGEMENT</p>
          <h3>Security Projects</h3>
          <p className="subtitle">Create and manage your security projects.</p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h4>Create Project</h4>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          <label>Project Name</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Enter project name"
            required
          />

          <label>Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe this project"
            rows={3}
          />

          {error && <p role="alert">{error}</p>}

          <button className="primary-button" disabled={saving}>
            {saving ? "Creating..." : "Create Project"}
          </button>
        </form>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h4>Registered Projects</h4>
          <span>{projects.length} projects</span>
        </div>

        {projects.length === 0 ? (
          <div className="empty-state">No projects registered yet.</div>
        ) : (
          <div className="asset-list">
            {projects.map((project) => (
              <div className="asset-row" key={project.id}>
                <div>
                  <strong>{project.name}</strong>
                  <span>{project.description || "No description"}</span>
                </div>
                <span className="asset-type">#{project.id}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
