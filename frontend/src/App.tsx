import { useEffect, useState } from "react";

import {
  getProjects,
  getAssets,
  getScans,
  getFindings,
  createScan,
  runScan,
} from "./api";

import Vulnerabilities from "./Vulnerabilities";
import Remediation from "./Remediation";
import Notifications from "./Notifications";

import "./App.css";


type Page =
  | "dashboard"
  | "vulnerabilities"
  | "remediation"
  | "notifications";


type Project = {
  id: number;
  name: string;
  description?: string | null;
};


type Asset = {
  id: number;
  name: string;
  asset_type: string;
  target: string;
  project_id: number;
};


type Scan = {
  id: number;
  asset_id: number;
  scanner: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
};


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


function App() {

  /* ===================================== */
  /* PAGE STATE                            */
  /* ===================================== */

  const [currentPage, setCurrentPage] =
    useState<Page>("dashboard");


  /* ===================================== */
  /* DASHBOARD DATA                        */
  /* ===================================== */

  const [projects, setProjects] =
    useState<Project[]>([]);

  const [assets, setAssets] =
    useState<Asset[]>([]);

  const [scans, setScans] =
    useState<Scan[]>([]);

  const [findings, setFindings] =
    useState<Finding[]>([]);


  /* ===================================== */
  /* LOADING / MESSAGE                     */
  /* ===================================== */

  const [loading, setLoading] =
    useState(true);

  const [message, setMessage] =
    useState("");


  /* ===================================== */
  /* SCAN MODAL                            */
  /* ===================================== */

  const [showScanModal, setShowScanModal] =
    useState(false);

  const [selectedAssetId, setSelectedAssetId] =
    useState<number | null>(null);

  const [scanScanner, setScanScanner] =
    useState("trivy");

  const [scanLoading, setScanLoading] =
    useState(false);


  /* ===================================== */
  /* INITIAL LOAD                          */
  /* ===================================== */

  useEffect(() => {
    loadDashboardData();
  }, []);


  /* ===================================== */
  /* LOAD DASHBOARD DATA                   */
  /* ===================================== */

  async function loadDashboardData() {

    try {

      setLoading(true);
      setMessage("");


      const [
        projectsData,
        assetsData,
        scansData,
        findingsData,
      ] = await Promise.all([
        getProjects(),
        getAssets(),
        getScans(),
        getFindings(),
      ]);


      setProjects(projectsData);
      setAssets(assetsData);
      setScans(scansData);
      setFindings(findingsData);

    } catch (error) {

      console.error(
        "Failed to load dashboard data:",
        error
      );


      setMessage(
        error instanceof Error
          ? error.message
          : "Failed to load dashboard data."
      );

    } finally {

      setLoading(false);

    }
  }


  /* ===================================== */
  /* OPEN SCAN MODAL                       */
  /* ===================================== */

  function openScanModal() {

    setMessage("");


    setSelectedAssetId(
      assets.length > 0
        ? assets[0].id
        : null
    );


    setScanScanner("trivy");

    setShowScanModal(true);
  }


  /* ===================================== */
  /* START SECURITY SCAN                  */
  /* ===================================== */

  async function handleStartScan() {

    if (!selectedAssetId) {

      setMessage(
        "Please select an asset."
      );

      return;
    }


    try {

      setScanLoading(true);
      setMessage("");


      /* CREATE SCAN RECORD */

      const newScan =
        await createScan(
          selectedAssetId,
          scanScanner
        );


      /* RUN REAL TRIVY SCAN */

      await runScan(
        newScan.id
      );


      setMessage(
        "Security scan completed successfully."
      );


      setShowScanModal(false);


      /* REFRESH DASHBOARD */

      await loadDashboardData();

    } catch (error) {

      console.error(
        "Scan failed:",
        error
      );


      setMessage(
        error instanceof Error
          ? error.message
          : "Security scan failed."
      );

    } finally {

      setScanLoading(false);

    }
  }


  /* ===================================== */
  /* RISK CALCULATIONS                     */
  /* ===================================== */

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


  const averageRisk =
    findings.length > 0
      ? (
          findings.reduce(
            (
              total,
              finding
            ) =>
              total +
              (
                finding.risk_score ??
                0
              ),
            0
          ) /
          findings.length
        ).toFixed(1)
      : "0.0";


  const completedScans =
    scans.filter(
      (scan) =>
        scan.status === "completed"
    ).length;


  /* ===================================== */
  /* UI                                     */
  /* ===================================== */

  return (

    <div className="app-shell">


      {/* ===================================== */}
      {/* SIDEBAR                               */}
      {/* ===================================== */}

      <aside className="sidebar">


        {/* BRAND */}

        <div className="brand">

          <div className="brand-mark">
            I
          </div>


          <div>

            <h1>
              INSPECTRA
            </h1>

            <span>
              Security Intelligence
            </span>

          </div>

        </div>


        {/* NAVIGATION */}

        <nav className="sidebar-nav">

          <p className="nav-section-title">
            PLATFORM
          </p>


          {/* DASHBOARD */}

          <button
            className={
              currentPage === "dashboard"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setCurrentPage(
                "dashboard"
              )
            }
          >

            <span className="nav-icon">
              ◈
            </span>

            Dashboard

          </button>


          {/* VULNERABILITIES */}

          <button
            className={
              currentPage ===
              "vulnerabilities"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setCurrentPage(
                "vulnerabilities"
              )
            }
          >

            <span className="nav-icon">
              ⚠
            </span>

            Vulnerabilities

          </button>


          {/* REMEDIATION */}

          <button
            className={
              currentPage ===
              "remediation"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setCurrentPage(
                "remediation"
              )
            }
          >

            <span className="nav-icon">
              ✓
            </span>

            Remediation

          </button>


          {/* NOTIFICATIONS */}

          <button
            className={
              currentPage ===
              "notifications"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setCurrentPage(
                "notifications"
              )
            }
          >

            <span className="nav-icon">
              ◉
            </span>

            Notifications

          </button>

        </nav>


        {/* SIDEBAR FOOTER */}

        <div className="sidebar-footer">

          <div className="system-status">

            <span className="status-dot" />

            <span>
              System Online
            </span>

          </div>


          <small>
            Inspectra v0.1
          </small>

        </div>

      </aside>


      {/* ===================================== */}
      {/* MAIN CONTENT                          */}
      {/* ===================================== */}

      <main className="main-content">


        {/* ================================= */}
        {/* TOP BAR                            */}
        {/* ================================= */}

        <header className="topbar">

          <div>

            <span className="topbar-label">
              SECURITY PLATFORM
            </span>


            <h2>

              {currentPage ===
                "dashboard" &&
                "Security Dashboard"}


              {currentPage ===
                "vulnerabilities" &&
                "Vulnerability Intelligence"}


              {currentPage ===
                "remediation" &&
                "Remediation Management"}


              {currentPage ===
                "notifications" &&
                "Notification Center"}

            </h2>

          </div>


          <div className="topbar-actions">

            <span className="environment-badge">
              LOCAL ENVIRONMENT
            </span>

          </div>

        </header>


        {/* ================================= */}
        {/* GLOBAL MESSAGE                     */}
        {/* ================================= */}

        {message && (

          <div className="global-message">
            {message}
          </div>

        )}


        {/* ================================= */}
        {/* DASHBOARD                          */}
        {/* ================================= */}

        {currentPage ===
          "dashboard" && (

          <div className="dashboard-page">


            {/* DASHBOARD HEADER */}

            <div className="page-header">

              <div>

                <p className="panel-label">
                  SECURITY OVERVIEW
                </p>


                <h3>
                  Security Operations
                </h3>


                <p className="subtitle">
                  Monitor assets, scans,
                  vulnerabilities and risk
                  across your environment.
                </p>

              </div>


              <button
                className="primary-button"
                onClick={
                  openScanModal
                }
                disabled={
                  assets.length === 0
                }
              >
                + New Security Scan
              </button>

            </div>


            {/* METRICS */}

            <div className="metrics-grid">


              {/* PROJECTS */}

              <div className="metric-card">

                <span>
                  Projects
                </span>


                <strong>
                  {loading
                    ? "—"
                    : projects.length}
                </strong>


                <small>
                  Active security projects
                </small>

              </div>


              {/* ASSETS */}

              <div className="metric-card">

                <span>
                  Assets
                </span>


                <strong>
                  {loading
                    ? "—"
                    : assets.length}
                </strong>


                <small>
                  Registered assets
                </small>

              </div>


              {/* SCANS */}

              <div className="metric-card">

                <span>
                  Scans
                </span>


                <strong>
                  {loading
                    ? "—"
                    : completedScans}
                </strong>


                <small>
                  Completed scans
                </small>

              </div>


              {/* VULNERABILITIES */}

              <div className="metric-card">

                <span>
                  Vulnerabilities
                </span>


                <strong>
                  {loading
                    ? "—"
                    : findings.length}
                </strong>


                <small>
                  Detected findings
                </small>

              </div>

            </div>


            {/* ================================= */}
            {/* DASHBOARD GRID                    */}
            {/* ================================= */}

            <div className="dashboard-grid">


              {/* ================================= */}
              {/* RISK INTELLIGENCE                */}
              {/* ================================= */}

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="panel-label">
                      RISK INTELLIGENCE
                    </p>


                    <h4>
                      Current Security Risk
                    </h4>

                  </div>


                  <span className="live-badge">
                    ● LIVE
                  </span>

                </div>


                <div className="risk-summary">


                  {/* AVERAGE RISK */}

                  <div className="risk-score">

                    <strong>
                      {averageRisk}
                    </strong>


                    <span>
                      Average Risk
                    </span>

                  </div>


                  {/* RISK BREAKDOWN */}

                  <div className="risk-breakdown">


                    {/* CRITICAL */}

                    <div>

                      <span className="critical-dot" />

                      <span>
                        Critical
                      </span>


                      <strong>
                        {criticalCount}
                      </strong>

                    </div>


                    {/* HIGH */}

                    <div>

                      <span className="high-dot" />

                      <span>
                        High
                      </span>


                      <strong>
                        {highCount}
                      </strong>

                    </div>


                    {/* OTHER */}

                    <div>

                      <span className="normal-dot" />

                      <span>
                        Other
                      </span>


                      <strong>
                        {Math.max(
                          findings.length -
                            criticalCount -
                            highCount,
                          0
                        )}
                      </strong>

                    </div>

                  </div>

                </div>

              </div>


              {/* ================================= */}
              {/* RECENT SCANS                     */}
              {/* ================================= */}

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="panel-label">
                      SCAN ACTIVITY
                    </p>


                    <h4>
                      Recent Scans
                    </h4>

                  </div>

                </div>


                {scans.length === 0 ? (

                  <div className="empty-state">

                    <strong>
                      No scans yet
                    </strong>


                    <span>
                      Start a security scan
                      to analyze an asset.
                    </span>

                  </div>

                ) : (

                  <div className="scan-list">

                    {scans
                      .slice(-5)
                      .reverse()
                      .map(
                        (scan) => (

                          <div
                            className="scan-row"
                            key={scan.id}
                          >

                            <div>

                              <strong>
                                Scan #{scan.id}
                              </strong>


                              <span>
                                {scan.scanner}
                              </span>

                            </div>


                            <span
                              className={`scan-status ${scan.status}`}
                            >
                              {scan.status}
                            </span>

                          </div>

                        )
                      )}

                  </div>

                )}

              </div>

            </div>


            {/* ================================= */}
            {/* ASSET INVENTORY                  */}
            {/* ================================= */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <p className="panel-label">
                    ASSET INVENTORY
                  </p>


                  <h4>
                    Registered Assets
                  </h4>

                </div>


                <span>
                  {assets.length} assets
                </span>

              </div>


              {assets.length === 0 ? (

                <div className="empty-state">

                  <strong>
                    No assets registered
                  </strong>


                  <span>
                    Add an asset before
                    starting a security scan.
                  </span>

                </div>

              ) : (

                <div className="asset-list">

                  {assets.map(
                    (asset) => (

                      <div
                        className="asset-row"
                        key={asset.id}
                      >

                        <div>

                          <strong>
                            {asset.name}
                          </strong>


                          <span>
                            {asset.target}
                          </span>

                        </div>


                        <span className="asset-type">
                          {asset.asset_type}
                        </span>

                      </div>

                    )
                  )}

                </div>

              )}

            </div>

          </div>

        )}


        {/* ================================= */}
        {/* VULNERABILITIES                    */}
        {/* ================================= */}

        {currentPage ===
          "vulnerabilities" && (

          <Vulnerabilities />

        )}


        {/* ================================= */}
        {/* REMEDIATION                        */}
        {/* ================================= */}

        {currentPage ===
          "remediation" && (

          <Remediation />

        )}


        {/* ================================= */}
        {/* NOTIFICATIONS                      */}
        {/* ================================= */}

        {currentPage ===
          "notifications" && (

          <Notifications />

        )}

      </main>


      {/* ===================================== */}
      {/* NEW SECURITY SCAN MODAL              */}
      {/* ===================================== */}

      {showScanModal && (

        <div className="modal-overlay">

          <div className="modal-card">


            {/* MODAL HEADER */}

            <div className="modal-header">

              <div>

                <p className="panel-label">
                  SCAN ORCHESTRATOR
                </p>


                <h3>
                  New Security Scan
                </h3>

              </div>


              <button
                className="modal-close"
                onClick={() =>
                  setShowScanModal(
                    false
                  )
                }
              >
                ×
              </button>

            </div>


            {/* MODAL BODY */}

            <div className="modal-body">


              {/* ASSET */}

              <label>
                Asset
              </label>


              <select
                value={
                  selectedAssetId ??
                  ""
                }
                onChange={(event) =>
                  setSelectedAssetId(
                    Number(
                      event.target.value
                    )
                  )
                }
              >

                <option value="">
                  Select an asset
                </option>


                {assets.map(
                  (asset) => (

                    <option
                      key={asset.id}
                      value={asset.id}
                    >
                      {asset.name}
                    </option>

                  )
                )}

              </select>


              {/* SCANNER */}

              <label>
                Scanner
              </label>


              <select
                value={scanScanner}
                onChange={(event) =>
                  setScanScanner(
                    event.target.value
                  )
                }
              >

                <option value="trivy">
                  Trivy
                </option>

              </select>

            </div>


            {/* MODAL FOOTER */}

            <div className="modal-footer">


              <button
                className="secondary-button"
                onClick={() =>
                  setShowScanModal(
                    false
                  )
                }
                disabled={
                  scanLoading
                }
              >
                Cancel
              </button>


              <button
                className="primary-button"
                onClick={
                  handleStartScan
                }
                disabled={
                  scanLoading ||
                  !selectedAssetId
                }
              >

                {scanLoading
                  ? "Scanning..."
                  : "Start Scan"}

              </button>

            </div>

          </div>

        </div>

      )}

    </div>

  );
}


export default App;