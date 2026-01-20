import React, { useState, useEffect } from "react";
import "./App.css";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";


const API = "http://localhost:8080";

function App() {
  const navigate = useNavigate();

  const [user, setUser] = useState(null);

  // auth
  const [authTab, setAuthTab] = useState("login");
  const [activeTab, setActiveTab] = useState("profile");

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // new fields
  const [department, setDepartment] = useState("");
  const [phone, setPhone] = useState("");
  const [address, setAddress] = useState("");

  // Profile edit
  const [editName, setEditName] = useState("");
  const [editEmail, setEditEmail] = useState("");
  const [editDepartment, setEditDepartment] = useState("");
  const [editPhone, setEditPhone] = useState("");
  const [editAddress, setEditAddress] = useState("");

  // Users for admin
  const [users, setUsers] = useState([]);

  // Leave request
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [leaveType, setLeaveType] = useState("");
  const [comment, setComment] = useState("");
  //const [leadId, setLeadId] = useState("");

  const [leads, setLeads] = useState([]);
  const [managers, setManagers] = useState([]);
 // const [managerId, setManagerId] = useState("");
  const [requests, setRequests] = useState([]);

  const [isEditingProfile, setIsEditingProfile] = useState(false);
  const [editingUserId, setEditingUserId] = useState(null);

  //admin user tab
  const USERS_PER_PAGE = 10;
  const [currentPage, setCurrentPage] = useState(1);

  const totalUsers = users.length;
  const totalPages = Math.ceil(totalUsers / USERS_PER_PAGE);

  const paginatedUsers = users
    .sort((a, b) => b.id - a.id)
    .slice(
      (currentPage - 1) * USERS_PER_PAGE,
      currentPage * USERS_PER_PAGE
    );

  //alert message
  const [alertMsg, setAlertMsg] = useState("");
  const [showAlert, setShowAlert] = useState(false);
  const [alertOnConfirm, setAlertOnConfirm] = useState(null);

  //popup
  const [popupMsg, setPopupMsg] = useState("");
  const [popupType, setPopupType] = useState("success");

  //date
  const today = new Date().toISOString().split("T")[0];

  // Admin create user
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newDepartment, setNewDepartment] = useState("");
  const [newRole, setNewRole] = useState("");
  const [newPhoto, setNewPhoto] = useState(null);
  const [newTeamLeadId, setNewTeamLeadId] = useState("");
  const [newManagerId, setNewManagerId] = useState("");

  const [showCreateUser, setShowCreateUser] = useState(false);

  const [showPhotoMenu, setShowPhotoMenu] = useState(false);

  //password
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showChangePassword, setShowChangePassword] = useState(false);
  
  const [showZoom, setShowZoom] = useState(false);

  //reject comment
  const [showRejectPopup, setShowRejectPopup] = useState(false);
  const [rejectComment, setRejectComment] = useState("");
  const [rejectRequestId, setRejectRequestId] = useState(null);
  const [rejectBy, setRejectBy] = useState("");

  //edit request
  const [isEditMode, setIsEditMode] = useState(false);
  const [editingRequestId, setEditingRequestId] = useState(null);


  
  const AlertUI = showAlert && (
    <div className="alert-overlay">
      <div className="alert-box">
        <p>{alertMsg}</p>
        <div className="alert-actions">
          <button
            className="btn success"
            onClick={() => {
              setShowAlert(false);
              if (alertOnConfirm) {
                alertOnConfirm();
                setAlertOnConfirm(null);
              }
            }}
          >
            OK
          </button>

          {/* Cancel only if this is a confirmation alert */}
          {alertOnConfirm && (
            <button
              className="btn danger"
              onClick={() => {
                setShowAlert(false);
                setAlertOnConfirm(null);
              }}
            >
              Cancel
            </button>
          )}
        </div>
      </div>
    </div>
  );


  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    fetch(`${API}/me`, { headers: { Authorization: `Bearer ${token}` } })
      .then(res => res.ok ? res.json() : Promise.reject())
      .then(user => {
        setUser(user);
        setEditName(user.name);
        setEditEmail(user.email);
        setEditDepartment(user.department);
        setEditPhone(user.phone);
        setEditAddress(user.address);

        fetchRequests(token);
        fetchLeads(token);
        if (user.role === "lead") fetchManagers(token);
        if (user.role === "admin") fetchUsers(token);
      })
      .catch(() => {
        localStorage.removeItem("token");
        setUser(null);
      });
      // eslint-disable-next-line
  }, []);

  useEffect(() => {
  if (popupMsg) {
    const timer = setTimeout(() => {
      setPopupMsg("");
    }, 3000);

    return () => clearTimeout(timer);
  }
}, [popupMsg]);

 useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      fetchLeads(token);
      fetchManagers(token);
    }
  }, []);



  /*request status*/
  const getStatusText = (r) => {
    if (r.status === "pending_lead" && user.role === "lead") return "Request received";
    if (r.status === "pending_manager" && user.role === "manager") return "Request received";

   /* if (r.status === "approved") {
      if (user.role === "associate") {
        if (r.manager_id) return "Approved by Manager";
        return "Approved by Team Lead";
      }
      return "Approved";
    }*/

    return r.status;
  };

  /* signup/login */
  const handleSignup = async (e) => {
    e.preventDefault();//prevent page reload on submit
    if (!name || !email || !password || !phone || !address) {
      setAlertMsg("Please fill all fields");
      setShowAlert(true);
      return;
    }

    try {
      const res = await fetch(`${API}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          password,
          department,
          phone,
          address,
        }),
      });

      if (!res.ok) {
        const err = await res.text();
        setAlertMsg(err || "Signup failed");
        setShowAlert(true);
        return;
      }

      setAlertMsg("User Created successfully. Please login.");
      setShowAlert(true);

      // reset fields
      setName("");
      setEmail("");
      setPassword("");
      setDepartment("");
      setPhone("");
      setAddress("");

      setAuthTab("login");
    } catch (e) {
      setAlertMsg("Server error. Please try again.");
      setShowAlert(true);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const res = await fetch(`${API}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      setAlertMsg("Invalid credentials");
      setShowAlert(true);
      //alert("Invalid credentials");
      return;
    }

    const data = await res.json();
    setUser(data.user);
    setEditName(data.user.name);
    setEditEmail(data.user.email);
    setEditDepartment(data.user.department || "");
    setEditPhone(data.user.phone || "");
    setEditAddress(data.user.address || "");


    localStorage.setItem("token", data.token);

    fetchRequests(data.token);
    fetchLeads(data.token);
    if (data.user.role === "lead") fetchManagers(data.token);
    if (data.user.role === "admin") fetchUsers(data.token);

    navigate("/dashboard");

  };

  const logout = () => {
    localStorage.removeItem("token");
    setUser(null);
    setUsers([]);     
    setActiveTab("profile");
  };

  /* fetch */
  const fetchRequests = async (tokenParam) => {
    const token = tokenParam || localStorage.getItem("token");
    if (!token) return;

    const res = await fetch(`${API}/requests`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    setRequests(data || []);
  };

  const fetchLeads = async (token) => {
    const res = await fetch(`${API}/team-leads`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    setLeads(data || []);
  };

  const fetchManagers = async (token) => {
    const res = await fetch(`${API}/managers`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    setManagers(data || []);
  };

  const fetchUsers = async (tokenParam) => {
    const token = tokenParam || localStorage.getItem("token"); //localStorage
    if (!token) return;

    const res = await fetch(`${API}/users`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401 || res.status === 403) {
      setAlertMsg("Session expired. Please login again.");
      setShowAlert(true);
      //alert("Session expired. Please login again.");
      logout();
      return;
    }

    const data = await res.json();
    setUsers(data || []);
  };

  /* profile tab */
  const updateProfile = async () => {
      const errors = [];
      if (!editEmail.trim()) errors.push("Email cannot be empty");
      if (!editPhone.trim()) errors.push("Phone number cannot be empty");
      if (!editName.trim()) errors.push("Name cannot be empty");
      if (!editDepartment.trim()) errors.push("Department cannot be empty");
      if (!editAddress.trim()) errors.push("Address cannot be empty");

      if (errors.length > 0) {
        setPopupMsg(errors.join("\n")); // messages separated by new line
        setPopupType("error");
        setTimeout(() => setPopupMsg(""), 4000); // hide after 4s
        return;
      }

      // email validation
      const isGmail = /^[^\s@]+@gmail\.com$/.test(editEmail);
      if (!isGmail) {
        setPopupMsg("Please enter a valid Gmail address");
        setPopupType("error");
        return;
      }
      //Phone: exactly 10 digits
      if (!/^\d{10}$/.test(editPhone)) {
        setPopupMsg("Phone number must be exactly 10 digits");
        setPopupType("error");
        return;
      }

      // max 100 characters
      if (editAddress.length > 100) {
        setPopupMsg("Address cannot exceed 100 characters");
        setPopupType("error");
        return;
      }

      const token = localStorage.getItem("token"); // get token

      await fetch(`${API}/users/${user.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: editName,
          email: editEmail,
          department: editDepartment, // new field
          phone: editPhone,           // new field
          address: editAddress        // new field
        }),
      });

      setUser({ 
        ...user, 
        name: editName, 
        email: editEmail,
        department: editDepartment, 
        phone: editPhone,
        address: editAddress
      });
      //alert("Profile updated");
      //setAlertMsg("Profile updated successfully");
      //setShowAlert(true);
      setPopupMsg("Profile updated successfully"); // message
      setPopupType("success");                     // optional type: success/error/info
      setTimeout(() => setPopupMsg(""), 3000); 
      setIsEditingProfile(false);

  };

  /* admin action */
  const deleteUser = async (id) => {
    const token = localStorage.getItem("token"); 

   // if (!window.confirm("Delete this user?")) return;

    try {
      const response = await fetch(`${API}/users/${id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) throw new Error("Failed to delete user");

      // Refresh user list
      fetchUsers(token);

      //setAlertMsg("User deleted successfully!");
      //setShowAlert(true);
      setPopupMsg("User deleted successfully!"); // message
      setPopupType("success");                     // optional type: success/error/info
      setTimeout(() => setPopupMsg(""), 3000)

    } catch (error) {
      console.error(error);

      setPopupMsg("Error deleting user!");
      setPopupType("error");

      setTimeout(() => setPopupMsg(""), 3000);
    }
  };

const deleteUserAndRequests = async (id) => {
  const token = localStorage.getItem("token");

  try {
    const response = await fetch(`${API}/users/delete-with-requests/${id}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) throw new Error("Failed to delete user and requests");

    fetchUsers(token); // refresh the user list
    setPopupMsg("User and requests deleted successfully!");
    setPopupType("success");
    setTimeout(() => setPopupMsg(""), 3000);

  } catch (error) {
    console.error(error);
    setPopupMsg("Error deleting user!");
    setPopupType("error");
    setTimeout(() => setPopupMsg(""), 3000);
  }
};

  const submitLeave = async () => {
  if (!fromDate || !toDate || !leaveType || !comment) {
    setAlertMsg("Please fill all fields");
    setShowAlert(true);
    return;
  }

  const payload = {
    employee_id: user.id,
    content: `${leaveType} (${fromDate} to ${toDate})`,
    comment: comment,
  };

  if (isEditMode && editingRequestId) {
    // resubmit rejected request
    await fetch(`${API}/request/${editingRequestId}/resubmit`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    setPopupMsg("Leave request updated and resubmitted");
  } else {
    // new request
    await fetch(`${API}/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    setPopupMsg("Leave request sent to Team Lead");
  }

  setFromDate("");
  setToDate("");
  setLeaveType("");
  setComment("");
  setIsEditMode(false);
  setEditingRequestId(null);

  setPopupType("success");
  fetchRequests();
};

  const leadReject = async (id, comment) => {
     const token = localStorage.getItem("token");

    await fetch(`${API}/lead-action/${id}?action=reject`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ rejection_comment: comment }),
    });

    setPopupMsg("❌ Rejected by Team Lead");
    setPopupType("error");

    fetchRequests();
  };


  const leadForward = async (id) => {
   const token = localStorage.getItem("token");

  await fetch(`${API}/lead-action/${id}?action=approve`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  setPopupMsg("Request forwarded to Manager");
  setPopupType("success");

  fetchRequests();
};


  const managerApprove = async (id) => {
    const token = localStorage.getItem("token");

    await fetch(`${API}/manager-action/${id}?action=approve`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
      },

    });

    setPopupMsg("✅ Leave approved successfully");
    setPopupType("success");

    fetchRequests();
  };


  const managerReject = async (id, comment) => {
    const token = localStorage.getItem("token");

    await fetch(`${API}/manager-action/${id}?action=reject`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ rejection_comment: comment }),
  });

  setPopupMsg("❌ Rejected by Manager");
  setPopupType("error");

  fetchRequests();
};

  
  //create user by admin
  const createUser = async () => {
     if (!newName || !newEmail || !newDepartment || !newRole || !newPhoto) {
      setAlertMsg("Please fill all fields & upload photo");
      setShowAlert(true);
      return;
    }
    const token = localStorage.getItem("token");

    try {
      const formData = new FormData();
      formData.append("name", newName);
      formData.append("email", newEmail);
      formData.append("department", newDepartment);
      formData.append("role", newRole);
      formData.append("photo", newPhoto);

      if (newRole === "associate" && newTeamLeadId) {
        formData.append("team_lead_id", newTeamLeadId);
      }

      if ((newRole === "associate" || newRole === "lead") && newManagerId) {
        formData.append("manager_id", newManagerId);
      }

      const response = await fetch(`${API}/admin/create-user`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData, 
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Create failed");

      fetchUsers(token);
      setNewName("");
      setNewEmail("");
      setNewDepartment("");
      setNewRole("");
      setNewPhoto(null);
      setNewTeamLeadId("");
      setNewManagerId(""); 

      setPopupMsg("User created successfully!");
      setPopupType("success");
      setShowCreateUser(false);

    }catch (err) {
      if (err.message.toLowerCase().includes("email")) {
        setPopupMsg("Email already exists. Please use a different email.");
      } else {
        setPopupMsg("Error creating user");
      }
      setPopupType("error");
    }

  };

  const handlePhotoUpload = async (file) => {
    if (!file) return;

    const token = localStorage.getItem("token");

    const formData = new FormData();
    formData.append("photo", file);

    const response = await fetch(`${API}/profile/photo`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      setPopupMsg(data.message || "Photo upload failed");
      setPopupType("error");
      return;
    }

    setUser(data.user); // updates pic
    setShowPhotoMenu(false);

    setPopupMsg("Profile photo Updated successfully!");
    setPopupType("success");
    setTimeout(() => setPopupMsg(""), 3000);
  };

  const handlePhotoDelete = async () => {
    const token = localStorage.getItem("token");

    try {
      const response = await fetch(`${API}/profile/photo`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        setPopupMsg(data.message || "Failed to delete photo");
        setPopupType("error");
        return;
      }

      setUser(data.user); // reset pic
      setShowPhotoMenu(false);

      // success popup here
      setPopupMsg("Profile photo removed successfully!");
      setPopupType("success");
      setTimeout(() => setPopupMsg(""), 3000);

    } catch (err) {
      setPopupMsg("Error deleting profile photo");
      setPopupType("error");
    }
  };

const handleChangePassword = async () => {
  if (!oldPassword || !newPassword || !confirmPassword) {
    setAlertMsg("Please fill all fields");
    setShowAlert(true);
    return;
  }
  if (newPassword !== confirmPassword) {
    setAlertMsg("New password and confirm password do not match");
    setShowAlert(true);
    return;
  }
  
    if (newPassword === oldPassword) {
    setAlertMsg("New password and Old password should not be same");
    setShowAlert(true);
    return;
  }

  const token = localStorage.getItem("token");
  const res = await fetch(`${API}/change-password`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ oldPassword, newPassword }),
  });

  const data = await res.json();

  if (!res.ok) {
    setAlertMsg(data.message || "Password change failed");
    setShowAlert("error");
    return;
  }

  setPopupMsg("Password changed successfully");
  setPopupType("success");

  setOldPassword("");
  setNewPassword("");
  setConfirmPassword("");
};

const parseContent = (content) => {
  if (!content) return {};

  // Expected format: "Casual Leave (2026-01-20 to 2026-01-21)"
  const match = content.match(
    /(.+?)\s*\((\d{4}-\d{2}-\d{2})\s*to\s*(\d{4}-\d{2}-\d{2})\)/
  );

  if (!match) return {};

  return {
    leaveType: match[1].trim(),
    fromDate: match[2],
    toDate: match[3],
  };
};


  /* ================= UI ================= */

return (
  <>
    {popupMsg && <div className={`popup ${popupType}`}>{popupMsg}</div>}
    <Routes>
      
      {/* LOGIN PAGE */}
      <Route
        path="/"
        element={
          user ? (
            <Navigate to="/dashboard" />
          ) : (
            <div className="app-container-auth-bg">
              {AlertUI}
              <h2 className="app-header">Employee Login / Signup</h2>

              <div className="auth-box">
                <div className="tabs">
                  <button
                    className={authTab === "login" ? "tab-btn active" : "tab-btn"}
                    onClick={() => {
                      setAuthTab("login");
                      setShowAlert(false);
                      setAlertMsg("");
                    }}
                  >
                    Login
                  </button>

                  <button
                    className={authTab === "signup" ? "tab-btn active" : "tab-btn"}
                    onClick={() => {
                      setAuthTab("signup");
                      setShowAlert(false);
                      setAlertMsg("");
                      // reset signup fields
                      setName("");
                      setEmail("");
                      setPassword("");
                      setDepartment("");
                      setPhone("");
                      setAddress("");
                    }}
                  >
                    Signup
                  </button>
                </div>

                  {authTab === "signup" && (
                    <form onSubmit={handleSignup}>
                      <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)}  autoComplete="off"/>
                      <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)}  autoComplete="off"/>
                      <input placeholder="Department" value={department} onChange={(e) => setDepartment(e.target.value)} />
                      <input type="tel" placeholder="Phone" value={phone} onChange={(e) => setPhone(e.target.value)} maxLength={10} pattern="\d{10}" title="Phone must be 10 digits"/>
                      <input placeholder="Address" value={address} onChange={(e) => setAddress(e.target.value)} />
                      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)}  />
                      <button className="btn" type="submit">Signup</button>
                    </form>
                  )}

                  {authTab === "login" && (
                    <form onSubmit={handleLogin}>
                      <input type="email" placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
                      <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} />
                      <button type="submit" className="btn">Login</button>
                    </form>
                  )}
              </div>
            </div>
          )
        }
      />

      {/* DASHBOARD PAGE */}
      <Route
        path="/dashboard"
        element={
          user ? (
            <div className="app-container-dashboard-bg">
              {AlertUI}
              <div className="content-card">
                <div className="top-bar">
                  <h2>Approval Management System</h2>
                  <div className="top-right">

                    <div
                      className="profile-photo-wrapper"
                      onMouseEnter={() => setShowPhotoMenu(true)}
                      onMouseLeave={() => setShowPhotoMenu(false)}
                    >
                      <img
                        src={
                          user?.photo_url
                            ? `${API}${user.photo_url}`
                            : `${API}/uploads/default.png`
                        }
                        alt="Profile"
                        className="profile-photo"
                        onClick={() => {
                          console.log("clicked");
                          setShowZoom(true);
                        }}
                      />

                      {showPhotoMenu && (
                        <div className="photo-overlay">
                          {/* Edit */}
                          <label className="icon-btn">
                            <i className="fas fa-pen"></i>
                            <input
                              type="file"
                              accept="image/*"
                              hidden
                              onChange={(e) => {
                                const file = e.target.files[0];
                                if (!file) return;

                                setAlertMsg("Do you want to change profile photo?");
                                setAlertOnConfirm(() => () => handlePhotoUpload(file));
                                setShowAlert(true);
                              }}
                            />
                          </label>

                          {/* Remove */}
                          {user?.photo_url && (
                            <button
                              className="icon-btn danger"
                              onClick={() => {
                                setAlertMsg("Are you sure you want to remove profile photo?");
                                setAlertOnConfirm(() => handlePhotoDelete);
                                setShowAlert(true);
                              }}
                            >
                              <i className="fas fa-trash"></i>
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                    {showZoom && (
                      <div className="modal-overlay" onClick={() => setShowZoom(false)}>
                        <img
                          src={
                            user?.photo_url
                              ? `${API}${user.photo_url}`
                              : `${API}/uploads/default.png`
                          }
                          alt="Zoomed Profile"
                          className="zoom-image"
                          onClick={(e) => e.stopPropagation()}
                        />
                      </div>
                    )}

                    <div className="profile-options">
                      <button className="btn danger" onClick={logout}>Logout</button>
                      <button className="btn" onClick={() => setShowChangePassword(true)}>
                        Change Password
                      </button>
                    </div>
                    {showChangePassword && (
                      <div className="modal-overlay">
                        <div className="change-password-card">
                          <h3>Change Password</h3>

                          {/* Old password */}
                          <div className="mui-field">
                            <input
                              type="password"
                              value={oldPassword}
                              onChange={(e) => setOldPassword(e.target.value)}
                              placeholder=" "
                            />
                            <label>Old Password</label>
                            <fieldset><legend>Old Password</legend></fieldset>
                          </div>

                          {/* New password */}
                          <div className="mui-field">
                            <input
                              type="password"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              placeholder=" "
                            />
                            <label>New Password</label>
                            <fieldset><legend>New Password</legend></fieldset>
                          </div>

                          {/* Confirm password */}
                          <div className="mui-field">
                            <input
                              type="password"
                              value={confirmPassword}
                              onChange={(e) => setConfirmPassword(e.target.value)}
                              placeholder=" "
                            />
                            <label>Confirm New Password</label>
                            <fieldset><legend>Confirm New Password</legend></fieldset>
                          </div>

                          <div className="change-password-actions">
                            <button className="btn success" onClick={handleChangePassword}>
                              Update Password
                            </button>
                            <button
                              className="btn danger"
                              onClick={() => {
                                setOldPassword("");
                                setNewPassword("");
                                setConfirmPassword("");
                                setShowChangePassword(false);
                              }}
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      </div>  
                    )}
                                     
                  </div>
                </div>

                <div className="tabs">
                  <button
                    className={activeTab === "profile" ? "tab-btn active" : "tab-btn"}
                    onClick={() => {
                      setActiveTab("profile");
                      setEditingUserId(null);
                    }}
                  >
                    Profile
                  </button>
                  {user.role !== "admin" && user.role !== "unassigned" && (
                    <button className={activeTab === "requests" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("requests")}>
                    Requests
                    </button>
                  )}
                  {user.role === "admin" && (
                    <button className={activeTab === "users" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("users")}>
                    Users
                    </button>
                  )}
                </div>
                
                {/* =================profile tab ===========================================================*/}
                {activeTab === "profile" && (
                  <div className="card profile-card">

                    {/* Header */}
                    <div className="profile-header">
                      <div>
                        <p><b>ID:</b> {user.id}</p>
                        <p><b>Role:</b> {user.role}</p>
                      </div>
                      
                      {!isEditingProfile && (
                        <span
                          className="edit-icon"
                          title="Edit Profile"
                          onClick={() => {
                            setEditName(user.name);
                            setEditEmail(user.email);
                            setEditDepartment(user.department || "");
                            setEditPhone(user.phone || "");
                            setEditAddress(user.address || "");
                            setIsEditingProfile(true);
                          }}
                        >
                          ✏️
                        </span>
                      )}
                    </div>

                    {/* Form */}
                    <div className="profile-form">
                      <div className="mui-field">
                        <input
                          value={editName}
                          disabled={!isEditingProfile}
                          onChange={(e) => setEditName(e.target.value)}
                          placeholder=" "
                        />
                        <label>Name</label>
                        <fieldset>
                          <legend>Name</legend>
                        </fieldset>
                      </div>

                      <div className="mui-field">
                        <input
                          type="email"
                          value={editEmail}
                          disabled={!isEditingProfile}
                          onChange={(e) => setEditEmail(e.target.value)}
                          placeholder=" "
                        />
                        <label>Email</label>
                        <fieldset><legend>Email</legend></fieldset>
                      </div>

                      <div className="mui-field">
                        <select
                          className={editDepartment ? "has-value" : ""}
                          data-readonly={!isEditingProfile}
                          value={editDepartment}
                          //disabled={!isEditingProfile}
                          onChange={(e) => isEditingProfile && setEditDepartment(e.target.value)}
                        >
                          <option value="" disabled></option>
                          <option value="HR">HR</option>
                          <option value="Engineering">Engineering</option>
                          <option value="Finance">Finance</option>
                          <option value="Marketing">Marketing</option>
                        </select>

                        <label>Department</label>
                        <fieldset><legend>Department</legend></fieldset>
                      </div>

                      <div className="mui-field">
                        <input
                          type="tel"
                          value={editPhone}
                          disabled={!isEditingProfile}
                          onChange={(e) => setEditPhone(e.target.value.replace(/\D/g, ""))}
                          maxLength={10}
                          placeholder=" "
                        />
                        <label>Phone</label>
                        <fieldset><legend>Phone</legend></fieldset>
                      </div>

                      <div className="mui-field full-width">
                        <textarea
                          value={editAddress}
                          disabled={!isEditingProfile}
                          onChange={(e) => setEditAddress(e.target.value.slice(0, 100))}
                          maxLength={100}
                          placeholder=" "
                        />
                        <label>Address</label>
                        <fieldset><legend>Address</legend></fieldset>
                      </div>
                    </div>

                    {/* Actions */}
                    {isEditingProfile && (
                      <div className="profile-actions">
                        <button
                          className="btn success"
                          onClick={() => {
                            //updateProfile();
                            setAlertMsg("Are you sure you want to save changes to your profile?");
                            setAlertOnConfirm(() => updateProfile);
                            setShowAlert(true);
                          }}
                        >
                          Save
                        </button>

                        <button
                          className="btn danger"
                          onClick={() => {
                            setEditName(user.name);
                            setEditEmail(user.email);
                            setEditDepartment(user.department || "");
                            setEditPhone(user.phone || "");
                            setEditAddress(user.address || "");
                            setIsEditingProfile(false);
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* ============================== requests tab ==================================== */}
                {activeTab === "requests" && (
                  <div className="card">
                    {user.role === "associate" && (
                      <>
                        <h3>Apply Leave</h3>
                        <div className="request-form-grid">
                          <div className="mui-field">
                            <input
                              type="date"
                              value={fromDate}
                              min={today}
                              onChange={(e) => {
                                setFromDate(e.target.value);
                                setToDate(""); // reset To Date if From Date changes
                              }}
                              placeholder=" "
                            />
                            <label>From Date</label>
                            <fieldset><legend>From Date</legend></fieldset>
                          </div>

                          <div className="mui-field">
                            <input
                              type="date"
                              value={toDate}
                              min={fromDate || today}
                              disabled={!fromDate}
                              onChange={(e) => setToDate(e.target.value)}
                              placeholder=" "
                            />
                            <label>To Date</label>
                            <fieldset><legend>To Date</legend></fieldset>
                          </div>

                          <div className="mui-field">
                            <select
                              value={leaveType}
                              onChange={(e) => setLeaveType(e.target.value)}
                              className={leaveType ? "has-value" : ""}
                            >
                              <option value="" disabled hidden></option>
                              <option value="Casual Leave">Casual Leave</option>
                              <option value="Earned Leave">Earned Leave</option>
                              <option value="CompOff">CompOff</option>
                            </select>
                            <label>Leave Type</label>
                            <fieldset><legend>Leave Type</legend></fieldset>
                          </div>

                          
                          <div className="mui-field">
                            <textarea
                              value={comment}
                              onChange={(e) => setComment(e.target.value)}
                              placeholder=" "
                            />
                            <label>Comment</label>
                            <fieldset><legend>Comment</legend></fieldset>
                          </div>


                          <div className="full-width" style={{ textAlign: "left", marginTop: "10px" }}>
                            <button className="btn" onClick={submitLeave}>
                              {isEditMode ? "Resubmit Leave" : "Submit Leave"}
                            </button>

                            {isEditMode && (
                              <button
                                type="button"
                                className="btn danger"
                                onClick={() => {
                                  setIsEditMode(false);
                                  setEditingRequestId(null);

                                  // reset form fields
                                  setLeaveType("");
                                  setComment("");
                                  setFromDate("");
                                  setToDate("");
                                }}
                              >
                                Cancel
                              </button>
                            )}

                          </div>

                        </div>
                        <h3>My Requests</h3>
                        <table>
                          <tbody>
                            {requests
                              .filter(r => r.employee_id === user.id)
                              .sort((a, b) => b.id - a.id) // descending order by id
                              .map(r => (
                                <tr key={r.id}>
                                  <td>{r.content}</td>
                                  <td>{getStatusText(r)}</td>
                                  <td>
                                    {r.status.startsWith("rejected") && r.rejection_comment  && (
                                      <div className="rejection-wrapper">
                                        <span className="rejection-text">{r.rejection_comment}</span>

                                        <i
                                          className="fa-solid fa-pen edit-icon"
                                          title="Edit & Resubmit"
                                          onClick={() => {
                                            setIsEditMode(true);
                                            setEditingRequestId(r.id);

                                            const parsed = parseContent(r.content);

                                            setLeaveType(parsed.leaveType || "");
                                            setFromDate(parsed.fromDate || "");
                                            setToDate(parsed.toDate || "");
                                            setComment(r.comment || "");

                                            window.scrollTo({ top: 0, behavior: "smooth" });
                                          }}
                                        />
                                      </div>
                                    )}
                                  </td>
                                </tr>
                            ))}
                          </tbody>
                        </table>
                      </>
                    )}

                    {(user.role === "lead" || user.role === "manager") && (
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
                              .sort((a, b) => b.id - a.id) // descending order by id
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
                                        <button className="btn success" onClick={() => leadForward(r.id)}>Approve</button>
                                        <button
                                          className="btn danger"
                                          onClick={() => {
                                            setRejectRequestId(r.id);
                                            setRejectBy("lead"); 
                                            setRejectComment("");
                                            setShowRejectPopup(true);
                                          }}
                                        >
                                          Reject
                                        </button>


                                      </>
                                    )}
                                    {user.role === "manager" && (
                                      <>
                                        <button className="btn" onClick={() => managerApprove(r.id)}>Approve</button>
                                        <button
                                            className="btn danger"
                                            onClick={() => {
                                              setRejectRequestId(r.id);
                                              setRejectBy("manager");
                                              setRejectComment("");
                                              setShowRejectPopup(true);
                                            }}
                                          >
                                            Reject
                                          </button>
                                        </>
                                    )}
                                  </td>
                                </tr>
                              ))}
                          </tbody>
                        </table>
                        {showRejectPopup && (
                          <div className="alert-overlay">
                            <div className="alert-box">
                              <h3>Reject Leave Request</h3>

                              <textarea
                                value={rejectComment}
                                onChange={(e) => setRejectComment(e.target.value)}
                                placeholder="Enter rejection reason"
                                style={{ width: "100%", minHeight: "80px" }}
                              />

                              <div style={{ marginTop: "20px", textAlign: "right" }}>
                                <button
                                  className="btn secondary"
                                  onClick={() => setShowRejectPopup(false)}
                                >
                                  Cancel
                                </button>

                                <button
                                  className="btn danger"
                                  disabled={!rejectComment.trim()}
                                  onClick={() => {
                                    rejectBy === "lead"
                                      ? leadReject(rejectRequestId, rejectComment)
                                      : managerReject(rejectRequestId, rejectComment);

                                    setRejectComment("");
                                    setRejectBy("");
                                    setShowRejectPopup(false);
                                  }}
                                >
                                  Reject
                                </button>
                              </div>
                            </div>
                          </div>
                        )}

                      </>
                    )}
                  </div>
                )}

                {/* ==========users tab(admin only)===================================================================*/}
                {activeTab === "users" && user.role === "admin" && (
                  <div className="card">
                    <div className="header-row">
                      <h3>User Management</h3>
                      <button
                        className="create-btn"
                        style={{ marginBottom: "16px" }}
                        onClick={() => setShowCreateUser(true)}
                      >
                        + Create User
                      </button>
                    </div>
                    {showCreateUser && (
                      <div className="modal-overlay">
                        <div className="modal-card">
                          <h4>Create New User</h4>

                          <div className="form-grid">
                            <div className="mui-field">
                              <input value={newName} onChange={e => setNewName(e.target.value)} placeholder=" "/>
                              <label>Name</label>
                              <fieldset><legend>Name</legend></fieldset>
                            </div>

                            <div className="mui-field">
                              <input type="email" value={newEmail} onChange={e => setNewEmail(e.target.value)} placeholder=" " />
                              <label>Email</label>
                              <fieldset><legend>Email</legend></fieldset>
                            </div>

                            <div className="mui-field">
                              <select
                                value={newDepartment}
                                onChange={(e) => setNewDepartment(e.target.value)}
                                className={newDepartment ? "has-value" : ""}
                              >
                                <option value="" disabled></option>
                                <option value="HR">HR</option>
                                <option value="Engineering">Engineering</option>
                                <option value="Finance">Finance</option>
                                <option value="Marketing">Marketing</option>
                              </select>

                              <label>Department</label>
                              <fieldset><legend>Department</legend></fieldset>
                            </div>

                            <div className="mui-field">
                              <select value={newRole} onChange={e => setNewRole(e.target.value)} className={newRole ? "has-value" : ""}>
                                <option value="" disabled hidden></option>
                                <option value="associate">Associate</option>
                                <option value="lead">Lead</option>
                                <option value="manager">Manager</option>
                                <option value="admin">Admin</option>
                              </select>
                              <label>Role</label>
                              <fieldset><legend>Role</legend></fieldset>
                            </div>

                            {newRole === "associate" && (
                              <div className="mui-field">
                                <select
                                  value={newTeamLeadId}
                                  onChange={(e) => setNewTeamLeadId(e.target.value)}
                                  className={newTeamLeadId ? "has-value" : ""}
                                >
                                  <option value="" disabled hidden></option>
                                  {leads.map(tl => (
                                    <option key={tl.id} value={tl.id}>{tl.name}</option>
                                  ))}
                                </select>
                                <label>Team Lead</label>
                                <fieldset><legend>Team Lead</legend></fieldset>
                              </div>
                            )}
                             
                            {(newRole === "associate" || newRole === "lead") && (
                              <div className="mui-field">
                                <select
                                  value={newManagerId}
                                  onChange={(e) => setNewManagerId(e.target.value)}
                                  className={newManagerId ? "has-value" : ""}
                                >
                                  <option value="" disabled hidden></option> 
                                  {managers.map(m => (
                                    <option key={m.id} value={m.id}>{m.name}</option>
                                  ))}
                                </select>
                                <label>Manager</label>
                                <fieldset><legend>Manager</legend></fieldset>
                              </div>
                            )}

                            <div className="mui-field">
                              <input
                                type="file"
                                accept="image/*"
                                onChange={(e) => setNewPhoto(e.target.files[0])}
                              />
                              <label>Photo</label>
                            </div>

                          </div>

                          <div style={{ marginTop: "12px" }}>
                            <button className="btn success" onClick={createUser}>Create</button>
                            <button
                              className="btn danger"
                              style={{ marginLeft: "10px" }}
                              onClick={() => {
                                setNewName("");
                                setNewEmail("");
                                setNewDepartment("");
                                setNewRole("");
                                setNewTeamLeadId("");
                                setNewManagerId("");
                                setNewPhoto(null);
                                setShowCreateUser(false)
                              }}
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                  
                    <table className="user-table">
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Email</th>
                          <th>Department</th>
                          <th>Phone</th>
                          <th>Address</th>
                          <th>Role</th>
                          <th>Actions</th>
                        </tr>
                      </thead>

                      <tbody>
                        {paginatedUsers.map((u) => {
                          const isEditing = editingUserId === u.id;

                          return (
                            <tr key={u.id}>
                              {/* name */}
                              <td>
                                {isEditing ? (
                                  <input
                                    value={u.editName ?? u.name}
                                    onChange={(e) =>
                                      setUsers((prev) =>
                                        prev.map((usr) =>
                                          usr.id === u.id
                                            ? { ...usr, editName: e.target.value }
                                            : usr
                                        )
                                      )
                                    }
                                  />
                                ) : (
                                  u.name
                                )}
                              </td>

                              {/* email */}
                              <td>
                                {isEditing ? (
                                  <input
                                    value={u.editEmail ?? u.email}
                                    onChange={(e) =>
                                      setUsers((prev) =>
                                        prev.map((usr) =>
                                          usr.id === u.id
                                            ? { ...usr, editEmail: e.target.value }
                                            : usr
                                        )
                                      )
                                    }
                                  />
                                ) : (
                                  u.email
                                )}
                              </td>

                              {/* dept */}
                              <td>
                                {isEditing ? (
                                  <select
                                    value={u.editDepartment ?? u.department ?? ""}
                                    onChange={(e) =>
                                      setUsers((prev) =>
                                        prev.map((usr) =>
                                          usr.id === u.id
                                            ? { ...usr, editDepartment: e.target.value }
                                            : usr
                                        )
                                      )
                                    }
                                  >
                                    <option value="">Select</option>
                                    <option value="HR">HR</option>
                                    <option value="Engineering">Engineering</option>
                                    <option value="Finance">Finance</option>
                                    <option value="Marketing">Marketing</option>
                                  </select>
                                ) : (
                                  u.department || "-"
                                )}

                              </td>

                              {/* phone */}
                              <td>
                                {isEditing ? (
                                  <input
                                    value={u.editPhone ?? u.phone ?? ""}
                                    maxLength={10}
                                    onChange={(e) =>
                                      setUsers((prev) =>
                                        prev.map((usr) =>
                                          usr.id === u.id
                                            ? { ...usr, editPhone: e.target.value }
                                            : usr
                                        )
                                      )
                                    }
                                  />
                                ) : (
                                  u.phone || "-"
                                )}
                              </td>

                              {/* address */}
                              <td>
                                {isEditing ? (
                                  <input
                                    value={u.editAddress ?? u.address ?? ""}
                                    maxLength={100}
                                    onChange={(e) =>
                                      setUsers((prev) =>
                                        prev.map((usr) =>
                                          usr.id === u.id
                                            ? { ...usr, editAddress: e.target.value }
                                            : usr
                                        )
                                      )
                                    }
                                  />
                                ) : (
                                  u.address || "-"
                                )}
                              </td>

                              {/* role */}
                              <td>
                                {isEditing ? (
                                  <select
                                    value={u.editRole ?? u.role}
                                    onChange={(e) =>
                                      setUsers((prev) =>
                                        prev.map((usr) =>
                                          usr.id === u.id
                                            ? { ...usr, editRole: e.target.value }
                                            : usr
                                        )
                                      )
                                    }
                                  >
                                    <option value="unassigned">Unassigned</option>
                                    <option value="associate">Associate</option>
                                    <option value="lead">Lead</option>
                                    <option value="manager">Manager</option>
                                    <option value="admin">Admin</option>
                                  </select>
                                ) : (
                                  <span
                                    style={{
                                      color: u.role === "unassigned" ? "red" : "inherit",
                                      fontWeight:
                                        u.role === "unassigned" ? "600" : "normal",
                                    }}
                                  >
                                    {u.role}
                                  </span>
                                )}
                              </td>

                              {/* action-edit/delete */}
                              <td className="action-cell">
                                {!isEditing ? (
                                  <>
                                    <i
                                      className={`fa-solid fa-pen-to-square action-icon edit ${
                                        editingUserId && editingUserId !== u.id ? "disabled" : ""
                                      }`}
                                      title="Edit"
                                      onClick={() => {
                                        if (editingUserId && editingUserId !== u.id) return;
                                        setEditingUserId(u.id);
                                      }}
                                    ></i>

                                    <i
                                      className="fa-solid fa-trash action-icon delete"
                                      title="Delete"
                                      onClick={() => {
                                          // Get user's requests
                                          const userRequests = requests.filter(r => r.employee_id === u.id);

                                          if (userRequests.length > 0) {
                                            // get request IDs
                                            const requestIds = userRequests.map(r => r.id).join(", ");

                                            // Show alert with request IDs
                                            setAlertMsg(
                                              `Unable to delete User ${u.name} due to foreign key constraints.
                                               User has requests history with IDs [${requestIds}]. 
                                               Do you want to delete both the user and their requests?`
                                            );

                                            setAlertOnConfirm(() => () => deleteUserAndRequests(u.id));
                                          } else {
                                            setAlertMsg(`Are you sure you want to delete ${u.name}?`);
                                            setAlertOnConfirm(() => () => deleteUser(u.id));
                                          }

                                          setShowAlert(true);
                                        }}
                                    ></i>
                                  </>
                                ) : (
                                  <>
                                    <i
                                      className="fa-solid fa-check action-icon save"
                                      title="Save"
                                      onClick={async () => {
                                        setAlertMsg(`Are you sure you want to save changes to ${u.name}?`);
                                        setAlertOnConfirm(() => async () => {
                                        const email = u.editEmail ?? u.email;
                                        const phone = u.editPhone ?? u.phone;
                                        const address = u.editAddress ?? u.address;

                                        // Email  validate
                                        if (!/^[^\s@]+@gmail\.com$/.test(email)) {
                                          setAlertMsg("Please enter valid email format");
                                          setShowAlert(true);
                                          return;
                                        }

                                        // Phone: 10 digits
                                        if (!/^\d{10}$/.test(phone)) {
                                          setAlertMsg("Phone number must be 10 digits");
                                          setShowAlert(true);
                                          return;
                                        }

                                        // Address max length 100
                                        if (address && address.length > 100) {
                                          setAlertMsg("Address cannot exceed 100 characters");
                                          setShowAlert(true);
                                          return;
                                        }
                                        const token = localStorage.getItem("token");

                                        await fetch(`${API}/users/${u.id}`, {
                                          method: "PUT",
                                          headers: {
                                            "Content-Type": "application/json",
                                            Authorization: `Bearer ${token}`,
                                          },
                                          body: JSON.stringify({
                                            name: u.editName ?? u.name,
                                            email: u.editEmail ?? u.email,
                                            department:u.editDepartment ?? u.department,
                                            phone: u.editPhone ?? u.phone,
                                            address: u.editAddress ?? u.address,
                                            role: u.editRole ?? u.role,
                                          }),
                                        });

                                        setEditingUserId(null);
                                        fetchUsers(token);
                                        //setAlertMsg("User updated successfully");
                                        //setShowAlert(true);
                                        setPopupMsg("User updated successfully");
                                        setPopupType("success");
                                        setTimeout(() => setPopupMsg(""), 3000);
                                        });
                                      setShowAlert(true);
                                      }}
                                    ></i>

                                    <i
                                      className="fa-solid fa-xmark action-icon cancel"
                                      title="Cancel"
                                      onClick={() => {
                                        setEditingUserId(null);
                                        fetchUsers();
                                      }}
                                    ></i>
                                  </>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>

                    {/* footer */}
                    <div className="table-footer">
                      <div className="table-info">
                        {Math.min(currentPage * USERS_PER_PAGE, totalUsers)} /{" "}
                        {totalUsers}
                      </div>

                      <div className="pagination">
                        {Array.from(
                          { length: totalPages },
                          (_, i) => i + 1
                        ).map((page) => (
                          <span
                            key={page}
                            className={`page-number ${
                              page === currentPage ? "active" : ""
                            }`}
                            onClick={() => setCurrentPage(page)}
                          >
                            {page}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <Navigate to="/" />
          )
        }
      />

    </Routes>
  </>
);
}

export default App;
