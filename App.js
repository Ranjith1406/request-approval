import React, { useState } from "react";
import "./App.css";

const API = "http://localhost:8080";

function App() {
  const [user, setUser] = useState(null);

  // auth
  const [authTab, setAuthTab] = useState("login");
  const [activeTab, setActiveTab] = useState("profile");

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("associate");

  // leave request
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [leaveType, setLeaveType] = useState("");
  const [comment, setComment] = useState("");
  const [leadId, setLeadId] = useState("");

  const [leads, setLeads] = useState([]);
  const [managers, setManagers] = useState([]);
  const [managerId, setManagerId] = useState("");

  const [requests, setRequests] = useState([]);

  // Notifications for each role
  const [message, setMessage] = useState("");
  const [messageForUserId, setMessageForUserId] = useState(null); // associate
  const [messageForLead, setMessageForLead] = useState("");       // team lead
  const [messageForManager, setMessageForManager] = useState(""); // manager

  /* ================= STATUS DISPLAY ================= */
  const getStatusText = (r) => {
    if (r.status === "pending_lead" && user.role === "lead") return "📥 Request received";
    if (r.status === "pending_manager" && user.role === "manager") return "📥 Request received";

    if (r.status === "approved") {
      if (user.role === "associate") {
        if (r.manager_id) return "Approved by Manager";
        return "Approved by Team Lead";
      }
      return "Approved";
    }

    return r.status;
  };

  /* ================= AUTH ================= */
  const handleSignup = async () => {
    await fetch(`${API}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password, role }),
    });
    alert("Signup successful. Please login.");
    setAuthTab("login");
  };

  const handleLogin = async () => {
    const res = await fetch(`${API}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      alert("Invalid credentials");
      return;
    }

    const data = await res.json();
    setUser(data);
    fetchRequests();
    fetchLeads();
    if (data.role === "lead") fetchManagers();
  };

  const logout = () => {
    setUser(null);
    setEmail("");
    setPassword("");
    setRequests([]);
    setMessage("");
    setMessageForUserId(null);
    setMessageForLead("");
    setMessageForManager("");
  };

  /* ================= FETCH ================= */
  const fetchRequests = async () => {
    const res = await fetch(`${API}/requests`);
    const data = await res.json();
    setRequests(data || []);
  };

  const fetchLeads = async () => {
    const res = await fetch(`${API}/team-leads`);
    const data = await res.json();
    setLeads(data || []);
  };

  const fetchManagers = async () => {
    const res = await fetch(`${API}/managers`);
    const data = await res.json();
    setManagers(data || []);
  };

  /* ================= LEAVE ================= */
  const submitLeave = async () => {
    if (!fromDate || !toDate || !leaveType || !comment || !leadId) {
      alert("Please fill all fields");
      return;
    }

    await fetch(`${API}/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        employee_id: user.id,
        content: `${leaveType} (${fromDate} to ${toDate})`,
        lead_id: parseInt(leadId),
        comment: comment,
      }),
    });

    setFromDate("");
    setToDate("");
    setLeaveType("");
    setComment("");
    setLeadId("");
    setMessage("✅ Leave request sent to Team Lead");
    setMessageForUserId(user.id);
    fetchRequests();
  };

  /* ================= ACTIONS ================= */
  const leadApprove = async (id) => {
  await fetch(`${API}/lead-action/${id}?action=approve`, { method: "PUT" });
  setMessageForLead("✅ Approved by Team Lead"); // for lead
  setMessage("✅ Your leave approved by Team Lead"); // for associate
  const req = requests.find(r => r.id === id);
  if (req) setMessageForUserId(req.employee_id);
  fetchRequests();
};

const leadReject = async (id) => {
  const c = prompt("Enter rejection comment") || "";
  await fetch(`${API}/lead-action/${id}?action=reject`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ Comment: c }),
  });
  setMessageForLead("❌ Rejected by Team Lead"); // for lead
  setMessage(`❌ Your leave rejected by Team Lead: ${c}`); // for associate
  const req = requests.find(r => r.id === id);
  if (req) setMessageForUserId(req.employee_id);
  fetchRequests();
};

const leadForward = async (id) => {
  if (!managerId) {
    alert("Please select a manager");
    return;
  }

  await fetch(`${API}/lead-action/${id}?action=forward`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ManagerID: parseInt(managerId) }),
  });

  setManagerId("");
  setMessageForLead("➡️ Request forwarded to Manager"); // lead notification
  const req = requests.find(r => r.id === id);
  if (req) setMessage(`➡️ Your leave forwarded to Manager`); // associate
  if (req) setMessageForUserId(req.employee_id);
  fetchRequests();
};

const managerApprove = async (id) => {
  await fetch(`${API}/manager-approve/${id}`, { method: "PUT" });
  setMessageForManager("✅ Approved by Manager"); // manager notification
  const req = requests.find(r => r.id === id);
  if (req) {
    setMessage(`✅ Your leave approved by Manager`);
    setMessageForUserId(req.employee_id);
  }
  fetchRequests();
};


  /* ================= UI ================= */
  if (!user) {
    return (
      <div className="app-container">
        <h2 className="app-header">Employee Signup / Login</h2>
        <div className="auth-box">
          <div className="tabs">
            <button className={authTab === "login" ? "tab-btn active" : "tab-btn"} onClick={() => setAuthTab("login")}>Login</button>
            <button className={authTab === "signup" ? "tab-btn active" : "tab-btn"} onClick={() => setAuthTab("signup")}>Signup</button>
          </div>

          {authTab === "signup" && (
            <>
              <input placeholder="Name" onChange={(e) => setName(e.target.value)} />
              <input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
              <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} />
              <select onChange={(e) => setRole(e.target.value)}>
                <option value="associate">Associate</option>
                <option value="lead">Team Lead</option>
                <option value="manager">Manager</option>
              </select>
              <button className="btn" onClick={handleSignup}>Signup</button>
            </>
          )}

          {authTab === "login" && (
            <>
              <input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
              <input type="password" onChange={(e) => setPassword(e.target.value)} />
              <button className="btn" onClick={handleLogin}>Login</button>
            </>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <div className="top-bar">
        <h2>Approval System</h2>
        <button className="btn danger" onClick={logout}>Logout</button>
      </div>

      <div className="tabs">
        <button className={activeTab === "profile" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("profile")}>Profile</button>
        <button className={activeTab === "requests" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("requests")}>Requests</button>
      </div>

      {/* Notifications */}
      {user.role === "associate" && message && messageForUserId === user.id && (
        <div className="notification">{message}</div>
      )}
      {user.role === "lead" && messageForLead && (
        <div className="notification">{messageForLead}</div>
      )}
      {user.role === "manager" && messageForManager && (
        <div className="notification">{messageForManager}</div>
      )}

      {activeTab === "profile" && (
        <div className="card">
          <p><b>Name:</b> {user.name}</p>
          <p><b>ID:</b> {user.id}</p>
          <p><b>Email:</b> {user.email}</p>
          <p><b>Role:</b> {user.role}</p>
        </div>
      )}

      {activeTab === "requests" && (
        <div className="card">
          {user.role === "associate" && (
            <>
              <h3>Apply Leave</h3>
              <input type="date" value={fromDate} onChange={(e) => setFromDate(e.target.value)} />
              <input type="date" value={toDate} onChange={(e) => setToDate(e.target.value)} />

              <select value={leaveType} onChange={(e) => setLeaveType(e.target.value)}>
                <option value="">Select Leave Type</option>
                <option value="Casual Leave">Casual Leave</option>
                <option value="Earned Leave">Earned Leave</option>
                <option value="CompOff">CompOff</option>
              </select>

              <textarea placeholder="Comment" value={comment} onChange={(e) => setComment(e.target.value)} />

              <select value={leadId} onChange={(e) => setLeadId(e.target.value)}>
                <option value="">Select Team Lead</option>
                {leads.map(l => <option key={l.id} value={l.id}>{l.name}</option>)}
              </select>

              <button className="btn" onClick={submitLeave}>Submit</button>

              <h3>My Requests</h3>
              <table>
                <tbody>
                  {requests.filter(r => r.employee_id === user.id).map(r => (
                    <tr key={r.id}>
                      <td>{r.content}</td>
                      <td>{getStatusText(r)}</td>
                      <td>{r.status === "rejected" && r.comment ? `❌ ${r.comment}` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {user.role !== "associate" && (
            <>
              <h3>Pending Requests</h3>
              <table>
                <tbody>
                  {requests
                    .filter(r =>
                      user.role === "lead"
                        ? r.status === "pending_lead" && r.lead_id === user.id
                        : r.status === "pending_manager" && r.manager_id === user.id
                    )
                    .map(r => (
                      <tr key={r.id}>
                        <td>
                          <b>{r.employee_name}</b> (ID: {r.employee_id})<br />
                          {r.content}
                        </td>
                        <td>{getStatusText(r)}</td>
                        <td>
                          {user.role === "lead" && (
                            <>
                              <button className="btn" onClick={() => leadApprove(r.id)}>Approve</button>
                              <button className="btn danger" onClick={() => leadReject(r.id)}>Reject</button>

                              <select value={managerId} onChange={(e) => setManagerId(e.target.value)}>
                                <option value="">Select Manager</option>
                                {managers.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
                              </select>

                              <button className="btn" onClick={() => leadForward(r.id)}>Forward</button>
                            </>
                          )}
                          {user.role === "manager" && (
                            <button className="btn" onClick={() => managerApprove(r.id)}>Approve</button>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
