import { useEffect, useState } from "react";

import {
  getFindings,
  getRemediationTasks,
  createRemediationTask,
  updateRemediationStatus,
  updateRemediationAssignee,
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


type RemediationTask = {
  id: number;
  finding_id: number;
  title: string;
  description?: string | null;
  status: string;
  assignee?: string | null;
  due_date?: string | null;
  created_at: string;
  updated_at: string;
};


function Remediation() {

  const [findings, setFindings] =
    useState<Finding[]>([]);

  const [tasks, setTasks] =
    useState<RemediationTask[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [creatingId, setCreatingId] =
    useState<number | null>(null);

  const [updatingId, setUpdatingId] =
    useState<number | null>(null);

  const [message, setMessage] =
    useState("");


  useEffect(() => {
    loadRemediationData();
  }, []);


  async function loadRemediationData() {

    try {

      setLoading(true);
      setMessage("");

      const [
        findingsData,
        tasksData,
      ] = await Promise.all([
        getFindings(),
        getRemediationTasks(),
      ]);

      setFindings(findingsData);
      setTasks(tasksData);

    } catch (error) {

      console.error(
        "Failed to load remediation data:",
        error
      );

      setMessage(
        error instanceof Error
          ? error.message
          : "Failed to load remediation data."
      );

    } finally {

      setLoading(false);

    }
  }


  function getTaskForFinding(
    findingId: number
  ) {

    return tasks.find(
      (task) =>
        task.finding_id === findingId
    );
  }


  async function createTask(
    finding: Finding
  ) {

    try {

      setCreatingId(finding.id);
      setMessage("");

      const newTask =
        await createRemediationTask(
          finding.id,

          finding.title ||
            `Remediate ${finding.vulnerability_id}`,

          finding.description ||
            `Remediation required for ${finding.vulnerability_id} affecting ${finding.package_name}.`,

          undefined,

          undefined
        );

      setTasks((current) => [
        newTask,
        ...current,
      ]);

      setMessage(
        `Remediation task #${newTask.id} created successfully.`
      );

    } catch (error) {

      console.error(
        "Failed to create remediation task:",
        error
      );

      setMessage(
        error instanceof Error
          ? error.message
          : "Failed to create remediation task."
      );

    } finally {

      setCreatingId(null);

    }
  }


  async function changeTaskStatus(
    taskId: number,
    status: string
  ) {

    try {

      setUpdatingId(taskId);
      setMessage("");

      const updated =
        await updateRemediationStatus(
          taskId,
          status
        );

      setTasks((current) =>
        current.map((task) =>
          task.id === updated.id
            ? updated
            : task
        )
      );

      setMessage(
        "Remediation task status updated successfully."
      );

    } catch (error) {

      console.error(
        "Failed to update remediation task:",
        error
      );

      setMessage(
        error instanceof Error
          ? error.message
          : "Failed to update remediation task."
      );

    } finally {

      setUpdatingId(null);

    }
  }


  async function assignTask(
    taskId: number,
    assignee: string
  ) {

    try {

      setUpdatingId(taskId);
      setMessage("");

      const updated =
        await updateRemediationAssignee(
          taskId,
          assignee || null
        );

      setTasks((current) =>
        current.map((task) =>
          task.id === updated.id
            ? updated
            : task
        )
      );

      setMessage(
        "Remediation assignment updated."
      );

    } catch (error) {

      console.error(
        "Failed to update assignee:",
        error
      );

      setMessage(
        error instanceof Error
          ? error.message
          : "Failed to update assignment."
      );

    } finally {

      setUpdatingId(null);

    }
  }


  const openCount =
    tasks.filter(
      (task) =>
        task.status === "open"
    ).length;


  const inProgressCount =
    tasks.filter(
      (task) =>
        task.status === "in_progress"
    ).length;


  const resolvedCount =
    tasks.filter(
      (task) =>
        task.status === "resolved" ||
        task.status === "closed"
    ).length;


  const remediationRate =
    tasks.length > 0
      ? Math.round(
          (resolvedCount / tasks.length) *
            100
        )
      : 0;


  const criticalCount =
    findings.filter(
      (finding) =>
        finding.severity === "CRITICAL"
    ).length;


  return (

    <div className="remediation-page">


      {/* ================================= */}
      {/* HEADER                            */}
      {/* ================================= */}

      <div className="remediation-header">

        <div>

          <p className="panel-label">
            SECURITY OPERATIONS
          </p>

          <h3>
            Remediation Management
          </h3>

          <p className="subtitle">
            Convert vulnerability findings into
            tracked remediation tasks and monitor
            their progress.
          </p>

        </div>


        <button
          className="secondary-button"
          onClick={loadRemediationData}
          disabled={loading}
        >
          ↻ Refresh
        </button>

      </div>


      {/* ================================= */}
      {/* METRICS                           */}
      {/* ================================= */}

      <div className="remediation-metrics">


        <div className="remediation-metric">

          <div className="remediation-metric-icon">
            ◌
          </div>

          <span>
            Open
          </span>

          <strong>
            {openCount}
          </strong>

          <small>
            Awaiting remediation
          </small>

        </div>


        <div className="remediation-metric">

          <div className="remediation-metric-icon">
            ◐
          </div>

          <span>
            In Progress
          </span>

          <strong>
            {inProgressCount}
          </strong>

          <small>
            Currently being fixed
          </small>

        </div>


        <div className="remediation-metric">

          <div className="remediation-metric-icon">
            ✓
          </div>

          <span>
            Resolved
          </span>

          <strong>
            {resolvedCount}
          </strong>

          <small>
            Successfully resolved
          </small>

        </div>


        <div className="remediation-metric">

          <div className="remediation-metric-icon">
            %
          </div>

          <span>
            Resolution Rate
          </span>

          <strong>
            {remediationRate}%
          </strong>

          <small>
            Tasks resolved
          </small>

        </div>

      </div>


      {/* ================================= */}
      {/* MESSAGE                            */}
      {/* ================================= */}

      {message && (

        <div className="remediation-message">
          {message}
        </div>

      )}


      {/* ================================= */}
      {/* MAIN CONTENT                       */}
      {/* ================================= */}

      <div className="remediation-overview">


        {/* ================================= */}
        {/* FINDINGS / TASK QUEUE              */}
        {/* ================================= */}

        <div className="panel">

          <div className="panel-header">

            <div>

              <p className="panel-label">
                REMEDIATION QUEUE
              </p>

              <h4>
                Vulnerability Actions
              </h4>

            </div>


            <span className="live-badge">
              ● LIVE
            </span>

          </div>


          {loading ? (

            <div className="remediation-empty">

              Loading remediation data...

            </div>


          ) : findings.length === 0 ? (

            <div className="remediation-empty">

              <div className="remediation-empty-icon">
                ✓
              </div>

              <strong>
                No vulnerability findings
              </strong>

              <span>
                Inspectra currently has no
                vulnerability findings requiring
                remediation.
              </span>

            </div>


          ) : (

            <div className="remediation-list">


              {findings.map(
                (finding) => {

                  const task =
                    getTaskForFinding(
                      finding.id
                    );


                  return (

                    <div
                      className="remediation-item"
                      key={finding.id}
                    >


                      {/* FINDING INFORMATION */}

                      <div className="remediation-item-main">

                        <div className="remediation-status-icon">

                          {task?.status ===
                          "resolved"
                            ? "✓"
                            : task?.status ===
                              "in_progress"
                            ? "◐"
                            : "!"}

                        </div>


                        <div className="remediation-info">

                          <strong>
                            {finding.vulnerability_id}
                          </strong>

                          <span>
                            {finding.title ||
                              "Security vulnerability"}
                          </span>

                          <small>
                            {finding.package_name}
                            {" · "}
                            {finding.installed_version}
                          </small>

                        </div>

                      </div>


                      {/* RISK */}

                      <div className="remediation-risk">

                        <span
                          className={`severity ${finding.severity.toLowerCase()}`}
                        >
                          {finding.severity}
                        </span>


                        <strong>

                          Risk{" "}

                          {finding.risk_score !==
                            null &&
                          finding.risk_score !==
                            undefined
                            ? finding.risk_score.toFixed(
                                1
                              )
                            : "—"}

                        </strong>


                        <span
                          className={`priority ${
                            finding.priority?.toLowerCase() ||
                            ""
                          }`}
                        >
                          {finding.priority ||
                            "—"}
                        </span>

                      </div>


                      {/* ACTION */}

                      <div className="remediation-action">


                        {!task ? (

                          <button
                            className="primary-button"
                            onClick={() =>
                              createTask(
                                finding
                              )
                            }
                            disabled={
                              creatingId ===
                              finding.id
                            }
                          >

                            {creatingId ===
                            finding.id
                              ? "Creating..."
                              : "Create Task"}

                          </button>


                        ) : (

                          <select
                            value={task.status}
                            disabled={
                              updatingId ===
                              task.id
                            }
                            onChange={(event) =>
                              changeTaskStatus(
                                task.id,
                                event.target.value
                              )
                            }
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

                            <option value="closed">
                              Closed
                            </option>

                          </select>

                        )}

                      </div>


                      {/* TASK DETAILS */}

                      {task && (

                        <div className="remediation-task-details">

                          <div>

                            <small>
                              Task
                            </small>

                            <strong>
                              #{task.id}
                            </strong>

                          </div>


                          <div>

                            <small>
                              Assignee
                            </small>

                            <input
                              type="text"
                              value={
                                task.assignee ||
                                ""
                              }
                              placeholder="Assign owner"
                              disabled={
                                updatingId ===
                                task.id
                              }
                              onBlur={(event) =>
                                assignTask(
                                  task.id,
                                  event.target.value
                                )
                              }
                            />

                          </div>

                        </div>

                      )}

                    </div>

                  );

                }
              )}

            </div>

          )}

        </div>


        {/* ================================= */}
        {/* SECURITY POSTURE                   */}
        {/* ================================= */}

        <div className="panel remediation-summary-panel">

          <div className="panel-header">

            <div>

              <p className="panel-label">
                SECURITY POSTURE
              </p>

              <h4>
                Remediation Summary
              </h4>

            </div>

          </div>


          <div className="remediation-summary">


            <div className="summary-circle">

              <strong>
                {remediationRate}%
              </strong>

              <span>
                Resolved
              </span>

            </div>


            <div className="summary-details">


              <div>

                <span>
                  Vulnerability findings
                </span>

                <strong>
                  {findings.length}
                </strong>

              </div>


              <div>

                <span>
                  Remediation tasks
                </span>

                <strong>
                  {tasks.length}
                </strong>

              </div>


              <div>

                <span>
                  Critical findings
                </span>

                <strong>
                  {criticalCount}
                </strong>

              </div>


              <div>

                <span>
                  Open tasks
                </span>

                <strong>
                  {openCount}
                </strong>

              </div>


              <div>

                <span>
                  Resolved tasks
                </span>

                <strong>
                  {resolvedCount}
                </strong>

              </div>

            </div>

          </div>


          {/* WORKFLOW NOTE */}

          <div className="remediation-note">

            <strong>
              Inspectra remediation workflow
            </strong>

            <p>
              A vulnerability finding can be
              converted into a tracked remediation
              task. Tasks can then be assigned,
              moved through Open, In Progress,
              Resolved and Closed states, and
              stored directly in the Inspectra
              backend.
            </p>

          </div>

        </div>

      </div>

    </div>

  );
}


export default Remediation;