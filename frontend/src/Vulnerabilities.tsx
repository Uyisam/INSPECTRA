import { useEffect, useState } from "react";
import {
  getFindings,
  updateFindingStatus,
} from "./api";

type Finding = {
  id: number;
  scan_id: number;
  vulnerability_id: string;
  package_name: string;
  installed_version: string;
  fixed_version?: string | null;
  severity: string;
  cvss_score?: number | null;
  title?: string | null;
  description?: string | null;
  primary_url?: string | null;
  target?: string | null;
  status: string;
  risk_score?: number | null;
  priority?: string | null;
};

function Vulnerabilities() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [priority, setPriority] = useState("ALL");

  const [selectedFinding, setSelectedFinding] =
    useState<Finding | null>(null);

  const [updatingStatus, setUpdatingStatus] =
    useState(false);

  const [statusMessage, setStatusMessage] =
    useState("");

  useEffect(() => {
    loadFindings();
  }, []);

  async function loadFindings() {
    try {
      setLoading(true);

      const data = await getFindings();

      setFindings(data);

      if (selectedFinding) {
        const updated = data.find(
          (item: Finding) =>
            item.id === selectedFinding.id
        );

        if (updated) {
          setSelectedFinding(updated);
        }
      }
    } catch (error) {
      console.error(
        "Failed to load vulnerabilities:",
        error
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleStatusChange(
    status: string
  ) {
    if (!selectedFinding) {
      return;
    }

    try {
      setUpdatingStatus(true);
      setStatusMessage("");

      const updated =
        await updateFindingStatus(
          selectedFinding.id,
          status
        );

      setSelectedFinding(updated);

      setFindings((currentFindings) =>
        currentFindings.map((finding) =>
          finding.id === updated.id
            ? updated
            : finding
        )
      );

      setStatusMessage(
        "Remediation status updated successfully."
      );
    } catch (error) {
      console.error(
        "Failed to update status:",
        error
      );

      setStatusMessage(
        error instanceof Error
          ? error.message
          : "Failed to update status."
      );
    } finally {
      setUpdatingStatus(false);
    }
  }

  const filteredFindings = findings.filter(
    (finding) => {
      const searchText =
        search.toLowerCase();

      const matchesSearch =
        finding.vulnerability_id
          .toLowerCase()
          .includes(searchText) ||
        finding.package_name
          .toLowerCase()
          .includes(searchText) ||
        (finding.title ?? "")
          .toLowerCase()
          .includes(searchText);

      const matchesSeverity =
        severity === "ALL" ||
        finding.severity === severity;

      const matchesPriority =
        priority === "ALL" ||
        finding.priority === priority;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesPriority
      );
    }
  );

  const criticalCount =
    findings.filter(
      (finding) =>
        finding.severity === "CRITICAL"
    ).length;

  const highCount =
    findings.filter(
      (finding) =>
        finding.severity === "HIGH"
    ).length;

  return (
    <div className="vulnerabilities-page">

      <div className="vulnerability-header">
        <div>
          <p className="panel-label">
            SECURITY FINDINGS
          </p>

          <h3>Vulnerabilities</h3>

          <p className="subtitle">
            Review, prioritize and manage detected
            security vulnerabilities.
          </p>
        </div>

        <button
          className="secondary-button"
          onClick={loadFindings}
          disabled={loading}
        >
          ↻ Refresh
        </button>
      </div>


      <div className="vulnerability-toolbar">

        <input
          type="text"
          placeholder="Search CVE, package or title..."
          value={search}
          onChange={(event) =>
            setSearch(event.target.value)
          }
        />

        <select
          value={severity}
          onChange={(event) =>
            setSeverity(event.target.value)
          }
        >
          <option value="ALL">
            All Severities
          </option>

          <option value="CRITICAL">
            Critical
          </option>

          <option value="HIGH">
            High
          </option>

          <option value="MEDIUM">
            Medium
          </option>

          <option value="LOW">
            Low
          </option>
        </select>


        <select
          value={priority}
          onChange={(event) =>
            setPriority(event.target.value)
          }
        >
          <option value="ALL">
            All Priorities
          </option>

          <option value="P0">
            P0
          </option>

          <option value="P1">
            P1
          </option>

          <option value="P2">
            P2
          </option>

          <option value="P3">
            P3
          </option>

          <option value="P4">
            P4
          </option>
        </select>

      </div>


      <div className="vulnerability-summary">

        <div>
          <span>Total Findings</span>
          <strong>
            {findings.length}
          </strong>
        </div>

        <div>
          <span>Showing</span>
          <strong>
            {filteredFindings.length}
          </strong>
        </div>

        <div>
          <span>Critical</span>
          <strong>
            {criticalCount}
          </strong>
        </div>

        <div>
          <span>High</span>
          <strong>
            {highCount}
          </strong>
        </div>

      </div>


      <div className="vulnerability-table">

        <div className="table-header">

          <span>Vulnerability</span>
          <span>Package</span>
          <span>Severity</span>
          <span>CVSS</span>
          <span>Risk</span>
          <span>Priority</span>
          <span>Status</span>

        </div>


        {loading ? (

          <div className="empty-vulnerability">

            <strong>
              Loading vulnerabilities...
            </strong>

          </div>

        ) : filteredFindings.length === 0 ? (

          <div className="empty-vulnerability">

            <div className="empty-icon">
              ✓
            </div>

            <strong>
              No vulnerabilities detected
            </strong>

            <span>
              Inspectra has no vulnerability
              findings matching the current filters.
            </span>

          </div>

        ) : (

          filteredFindings.map(
            (finding) => (

              <button
                className="table-row vulnerability-row-button"
                key={finding.id}
                onClick={() =>
                  setSelectedFinding(finding)
                }
              >

                <div>
                  <strong>
                    {finding.vulnerability_id}
                  </strong>

                  <span>
                    {finding.title ||
                      "Security vulnerability"}
                  </span>
                </div>


                <div>

                  <strong>
                    {finding.package_name}
                  </strong>

                  <span>
                    {finding.installed_version}
                  </span>

                </div>


                <span
                  className={`severity ${finding.severity.toLowerCase()}`}
                >
                  {finding.severity}
                </span>


                <span>
                  {finding.cvss_score !== null &&
                  finding.cvss_score !== undefined
                    ? finding.cvss_score.toFixed(1)
                    : "—"}
                </span>


                <strong>
                  {finding.risk_score !== null &&
                  finding.risk_score !== undefined
                    ? finding.risk_score.toFixed(1)
                    : "—"}
                </strong>


                <span
                  className={`priority ${
                    finding.priority?.toLowerCase() ||
                    ""
                  }`}
                >
                  {finding.priority || "—"}
                </span>


                <span className="finding-status">
                  {finding.status}
                </span>

              </button>

            )
          )

        )}

      </div>


      {selectedFinding && (

        <div
          className="finding-modal-overlay"
          onClick={() =>
            setSelectedFinding(null)
          }
        >

          <div
            className="finding-detail-panel"
            onClick={(event) =>
              event.stopPropagation()
            }
          >

            <div className="finding-detail-header">

              <div>

                <p className="panel-label">
                  VULNERABILITY DETAIL
                </p>

                <h4>
                  {selectedFinding.vulnerability_id}
                </h4>

                <span>
                  Finding #{selectedFinding.id}
                </span>

              </div>


              <button
                className="modal-close"
                onClick={() =>
                  setSelectedFinding(null)
                }
              >
                ×
              </button>

            </div>


            <div className="finding-detail-body">

              <div className="finding-title">
                <h5>
                  {selectedFinding.title ||
                    "Security vulnerability"}
                </h5>

                <div className="finding-badges">

                  <span
                    className={`severity ${selectedFinding.severity.toLowerCase()}`}
                  >
                    {selectedFinding.severity}
                  </span>

                  <span
                    className={`priority ${
                      selectedFinding.priority?.toLowerCase() ||
                      ""
                    }`}
                  >
                    {selectedFinding.priority ||
                      "UNASSIGNED"}
                  </span>

                </div>
              </div>


              <div className="detail-metrics">

                <div>
                  <span>CVSS</span>

                  <strong>
                    {selectedFinding.cvss_score !==
                      null &&
                    selectedFinding.cvss_score !==
                      undefined
                      ? selectedFinding.cvss_score.toFixed(
                          1
                        )
                      : "—"}
                  </strong>
                </div>


                <div>
                  <span>Risk Score</span>

                  <strong>
                    {selectedFinding.risk_score !==
                      null &&
                    selectedFinding.risk_score !==
                      undefined
                      ? selectedFinding.risk_score.toFixed(
                          1
                        )
                      : "—"}
                  </strong>
                </div>


                <div>
                  <span>Scan</span>

                  <strong>
                    #{selectedFinding.scan_id}
                  </strong>
                </div>

              </div>


              <div className="detail-section">

                <h6>Package Information</h6>

                <div className="detail-grid">

                  <div>
                    <span>
                      Package
                    </span>

                    <strong>
                      {selectedFinding.package_name}
                    </strong>
                  </div>


                  <div>
                    <span>
                      Installed Version
                    </span>

                    <strong>
                      {
                        selectedFinding.installed_version
                      }
                    </strong>
                  </div>


                  <div>
                    <span>
                      Fixed Version
                    </span>

                    <strong>
                      {selectedFinding.fixed_version ||
                        "No fixed version provided"}
                    </strong>
                  </div>


                  <div>
                    <span>
                      Target
                    </span>

                    <strong>
                      {selectedFinding.target ||
                        "Unknown"}
                    </strong>
                  </div>

                </div>

              </div>


              <div className="detail-section">

                <h6>Description</h6>

                <p className="finding-description">
                  {selectedFinding.description ||
                    "No vulnerability description was provided by the scanner."}
                </p>

              </div>


              <div className="detail-section remediation-section">

                <h6>
                  Remediation
                </h6>

                <label>
                  Current Status
                </label>

                <select
                  value={
                    selectedFinding.status
                  }
                  onChange={(event) =>
                    handleStatusChange(
                      event.target.value
                    )
                  }
                  disabled={updatingStatus}
                >

                  <option value="open">
                    Open
                  </option>

                  <option value="in_progress">
                    In Progress
                  </option>

                  <option value="resolved">
                    Resolved
                  </option>

                </select>


                {statusMessage && (

                  <div className="status-update-message">
                    {statusMessage}
                  </div>

                )}

              </div>


              {selectedFinding.primary_url && (

                <div className="detail-section">

                  <h6>
                    Security Reference
                  </h6>

                  <a
                    href={
                      selectedFinding.primary_url
                    }
                    target="_blank"
                    rel="noreferrer"
                    className="reference-link"
                  >
                    View vulnerability reference ↗
                  </a>

                </div>

              )}

            </div>

          </div>

        </div>

      )}

    </div>
  );
}

export default Vulnerabilities;