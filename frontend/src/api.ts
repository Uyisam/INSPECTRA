const API_BASE_URL = "http://127.0.0.1:8000";


export async function getProjects() {
  const response = await fetch(
    `${API_BASE_URL}/projects/`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch projects");
  }

  return response.json();
}


export async function getAssets() {
  const response = await fetch(
    `${API_BASE_URL}/assets/`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch assets");
  }

  return response.json();
}


export async function getScans() {
  const response = await fetch(
    `${API_BASE_URL}/scans/`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch scans");
  }

  return response.json();
}


export async function getFindings() {
  const response = await fetch(
    `${API_BASE_URL}/findings/`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch findings");
  }

  return response.json();
}


export async function createScan(
  assetId: number,
  scanner: string
) {
  const response = await fetch(
    `${API_BASE_URL}/scans/`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        asset_id: assetId,
        scanner: scanner,
      }),
    }
  );

  if (!response.ok) {
    throw new Error("Failed to create scan");
  }

  return response.json();
}


export async function runScan(
  scanId: number
) {
  const response = await fetch(
    `${API_BASE_URL}/scans/${scanId}/run`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    const errorData =
      await response.json().catch(() => null);

    throw new Error(
      errorData?.detail ||
        "Failed to run scan"
    );
  }

  return response.json();
}


/* ========================================= */
/* VULNERABILITY MANAGEMENT                  */
/* ========================================= */

export async function getFinding(
  findingId: number
) {
  const response = await fetch(
    `${API_BASE_URL}/findings/${findingId}`
  );

  if (!response.ok) {
    throw new Error(
      "Failed to fetch finding"
    );
  }

  return response.json();
}


export async function updateFindingStatus(
  findingId: number,
  status: string
) {
  const response = await fetch(
    `${API_BASE_URL}/findings/${findingId}/status`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        status: status,
      }),
    }
  );

  if (!response.ok) {
    const errorData =
      await response.json().catch(() => null);

    throw new Error(
      errorData?.detail ||
        "Failed to update finding status"
    );
  }

  return response.json();
}

/* ========================================= */
/* REMEDIATION MANAGEMENT                    */
/* ========================================= */

export async function getRemediationTasks() {
  const response = await fetch(
    `${API_BASE_URL}/remediation/`
  );

  if (!response.ok) {
    throw new Error(
      "Failed to fetch remediation tasks"
    );
  }

  return response.json();
}


export async function getRemediationTask(
  taskId: number
) {
  const response = await fetch(
    `${API_BASE_URL}/remediation/${taskId}`
  );

  if (!response.ok) {
    throw new Error(
      "Failed to fetch remediation task"
    );
  }

  return response.json();
}


export async function createRemediationTask(
  findingId: number,
  title: string,
  description?: string,
  assignee?: string,
  dueDate?: string
) {
  const response = await fetch(
    `${API_BASE_URL}/remediation/`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        finding_id: findingId,
        title: title,
        description: description ?? null,
        assignee: assignee ?? null,
        due_date: dueDate ?? null,
      }),
    }
  );

  if (!response.ok) {
    const errorData =
      await response.json().catch(() => null);

    throw new Error(
      errorData?.detail ||
        "Failed to create remediation task"
    );
  }

  return response.json();
}


export async function updateRemediationStatus(
  taskId: number,
  status: string
) {
  const response = await fetch(
    `${API_BASE_URL}/remediation/${taskId}/status`,
    {
      method: "PATCH",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        status: status,
      }),
    }
  );

  if (!response.ok) {
    const errorData =
      await response.json().catch(() => null);

    throw new Error(
      errorData?.detail ||
        "Failed to update remediation status"
    );
  }

  return response.json();
}


export async function updateRemediationAssignee(
  taskId: number,
  assignee: string | null
) {
  const response = await fetch(
    `${API_BASE_URL}/remediation/${taskId}/assignee`,
    {
      method: "PATCH",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        assignee: assignee,
      }),
    }
  );

  if (!response.ok) {
    const errorData =
      await response.json().catch(() => null);

    throw new Error(
      errorData?.detail ||
        "Failed to update remediation assignee"
    );
  }

  return response.json();
}


/* ========================================= */
/* NOTIFICATION MANAGEMENT                   */
/* ========================================= */

export async function getNotifications() {
  const response = await fetch(
    `${API_BASE_URL}/notifications/`
  );

  if (!response.ok) {
    throw new Error(
      "Failed to fetch notifications"
    );
  }

  return response.json();
}


export async function getUnreadNotifications() {
  const response = await fetch(
    `${API_BASE_URL}/notifications/unread`
  );

  if (!response.ok) {
    throw new Error(
      "Failed to fetch unread notifications"
    );
  }

  return response.json();
}


export async function updateNotificationReadStatus(
  notificationId: number,
  isRead: boolean
) {
  const response = await fetch(
    `${API_BASE_URL}/notifications/${notificationId}/read`,
    {
      method: "PATCH",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        is_read: isRead,
      }),
    }
  );

  if (!response.ok) {
    const errorData =
      await response.json().catch(() => null);

    throw new Error(
      errorData?.detail ||
        "Failed to update notification"
    );
  }

  return response.json();
}