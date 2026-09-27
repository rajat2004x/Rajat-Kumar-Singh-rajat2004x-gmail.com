import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const themes = { cobalt: '#d9e7ff', amber: '#f8e9bd', moss: '#dcebdc', plum: '#eadcf0', rust: '#f3ddd0', teal: '#d5eee9' };
const permissionLabels = { 'device:view': 'View', 'device:control': 'Control', 'device:terminal': 'Terminal', 'device:file_transfer': 'Transfer files', 'device:update': 'Rename', 'device:provision': 'Decommission' };

function displayError(error) {
  if (!error) return '';
  if (error.status === 403) return error.message || 'You do not have permission for this action.';
  if (error.status === 404) return 'That resource is not available in this organization.';
  if (error.status === 409) return error.message || 'That action conflicts with the current state.';
  if (error.status === 400) return error.message || 'Please check the submitted values.';
  return error.message || 'The service is not responding. Try again.';
}

function errorFromResponse(response, body) {
  const detail = body?.error;
  const error = new Error(detail?.message || `Request failed (${response.status})`);
  error.status = response.status;
  error.code = detail?.code;
  error.reason = detail?.reason;
  return error;
}

function useApi() {
  const token = useRef(null);
  const refreshInFlight = useRef(null);
  const refresh = async () => {
    if (!refreshInFlight.current) {
      refreshInFlight.current = fetch('/v1/auth/refresh', { method: 'POST', credentials: 'include' }).then(async (response) => {
        const body = await response.json().catch(() => ({}));
        if (!response.ok || !body.token) throw errorFromResponse(response, body);
        token.current = body.token;
        return body.token;
      }).finally(() => { refreshInFlight.current = null; });
    }
    return refreshInFlight.current;
  };
  const request = async (path, options = {}, retry = true) => {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
    if (token.current) headers.set('authorization', `Bearer ${token.current}`);
    const response = await fetch(`/v1${path}`, { ...options, headers, credentials: 'include', body: options.body && typeof options.body !== 'string' ? JSON.stringify(options.body) : options.body });
    const body = await response.json().catch(() => ({}));
    if (response.status === 401 && retry && path !== '/auth/refresh') {
      try { await refresh(); return request(path, options, false); } catch { token.current = null; }
    }
    if (!response.ok) throw errorFromResponse(response, body);
    return body;
  };
  return { request, refresh, setToken: (value) => { token.current = value; }, clearToken: () => { token.current = null; } };
}

function PermissionAction({ permission, testId, children, onClick }) {
  return <button className="action" data-testid={testId} data-permission={permission} data-state="unlocked" onClick={onClick} type="button">{children}</button>;
}

function Login({ onLogin, api }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const submit = async (event) => {
    event.preventDefault();
    setError(null);
    if (!email.trim() || !password) { setError({ message: 'Email and password are required', code: 'VALIDATION' }); return; }
    try {
      const result = await api.request('/auth/login', { method: 'POST', body: { email, password } }, false);
      api.setToken(result.token);
      await onLogin();
    } catch (reason) { setError(reason); }
  };
  return <main className="login-page"><section className="login-panel"><p className="eyebrow">REMOTEOPS / CONTROL PLANE</p><h1>Operate with context.</h1><p className="muted">Sign in to manage the organizations and devices assigned to you.</p><form data-testid="login-form" onSubmit={submit}><label>Email<input data-testid="login-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" /></label><label>Password<input data-testid="login-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>{error && <div className="error" data-testid="login-error" data-error-code={error.code || ''} role="alert">{displayError(error)}</div>}<button className="primary wide" data-testid="login-submit" type="submit">Sign in <span aria-hidden="true">&#8594;</span></button></form></section><aside className="login-aside"><span>01</span><strong>Authority follows the organization.</strong><p>One identity. Fresh permissions. No hidden shortcuts.</p></aside></main>;
}

function InvitePage({ api }) {
  const inviteToken = window.location.pathname.split('/')[2] || '';
  const [invite, setInvite] = useState(null);
  const [form, setForm] = useState({ name: '', password: '' });
  const [error, setError] = useState(null);
  const [accepted, setAccepted] = useState(false);
  useEffect(() => { api.request(`/invites/${encodeURIComponent(inviteToken)}`, {}, false).then(setInvite).catch(setError); }, []);
  const accept = async (event) => { event.preventDefault(); setError(null); try { await api.request(`/invites/${encodeURIComponent(inviteToken)}/accept`, { method: 'POST', body: form }, false); setAccepted(true); } catch (reason) { setError(reason); } };
  if (accepted) return <Login api={api} onLogin={() => { window.history.replaceState({}, '', '/'); window.location.reload(); }} />;
  return <main className="login-page"><section className="login-panel"><p className="eyebrow">REMOTEOPS / INVITATION</p><h1>Join your team.</h1>{invite && <p className="invite-copy">You have been invited to <strong>{invite.orgName}</strong> as <strong data-testid="invite-role">{invite.role}</strong>.</p>}{error && <div className="error" data-testid="invite-error" role="alert">{displayError(error)}</div>}{invite && <form onSubmit={accept}><label>Name<input data-testid="invite-name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label><label>Email<input data-testid="invite-email" value={invite.email} readOnly /></label><label>Password<input data-testid="invite-password" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label><button className="primary wide" data-testid="invite-submit" type="submit">Accept invitation <span aria-hidden="true">&#8594;</span></button></form>}</section></main>;
}

function Nav({ permissions, view, setView }) {
  const allowed = (permission) => permissions?.[permission]?.effect === 'allow';
  const items = [['devices', 'Devices', 'device:list'], ['people', 'People', 'user:read'], ['grants', 'Grants', 'user:read'], ['sessions', 'Sessions', 'session:view'], ['audit', 'Audit', 'audit:read']];
  return <nav className="nav-list">{items.filter((item) => allowed(item[2])).map(([key, label, permission]) => <button key={key} className={view === key ? 'nav-item active' : 'nav-item'} data-testid={`nav-${key}`} data-permission={permission} data-state="unlocked" onClick={() => setView(key)} type="button"><span>{label}</span><span aria-hidden="true">&#8594;</span></button>)}{(allowed('org:update') || allowed('org:delete')) && <button className={view === 'admin' ? 'nav-item active' : 'nav-item'} data-testid="nav-admin" onClick={() => setView('admin')} type="button"><span>Admin</span><span aria-hidden="true">&#8594;</span></button>}</nav>;
}

function DevicesView({ data, permissions, api, onChanged }) {
  const [error, setError] = useState(null);
  const allowed = (permission) => permissions?.[permission]?.effect === 'allow';
  const start = async (deviceId, mode) => { setError(null); try { await api.request(`/orgs/${data.orgId}/sessions`, { method: 'POST', body: { deviceId, mode } }); onChanged('sessions'); } catch (reason) { setError(reason); } };
  const rename = async (device) => { const name = window.prompt('New device name', device.name); if (!name) return; try { await api.request(`/orgs/${data.orgId}/devices/${device.id}`, { method: 'PATCH', body: { name } }); onChanged('devices'); } catch (reason) { setError(reason); } };
  const remove = async (device) => { if (!window.confirm(`Decommission ${device.name}?`)) return; try { await api.request(`/orgs/${data.orgId}/devices/${device.id}`, { method: 'DELETE' }); onChanged('devices'); } catch (reason) { setError(reason); } };
  return <section className="view"><div className="view-heading"><div><p className="eyebrow">INVENTORY / LIVE DEVICES</p><h2>Devices</h2></div>{allowed('device:provision') && <PermissionAction permission="device:provision" testId="add-device" onClick={() => setError({ message: 'Use the API to provision a device.' })}>Add device</PermissionAction>}</div>{error && <div className="error" role="alert">{displayError(error)}</div>}{!data.devices?.length ? <div className="empty" data-testid="devices-empty">No devices are connected to this organization yet.</div> : <div className="table-wrap"><table><thead><tr><th>Device</th><th>Type</th><th>Status</th><th>Actions</th></tr></thead><tbody>{data.devices.map((device) => <tr data-testid="device-row" data-device-id={device.id} key={device.id}><td><strong>{device.name}</strong><small>{device.id}</small></td><td>{device.kind}</td><td><span className={device.online ? 'status online' : 'status'}>{device.online ? 'Online' : 'Offline'}</span></td><td className="actions">{Object.entries(permissionLabels).map(([permission, label]) => { if (device.permissions?.[permission]?.effect !== 'allow') return null; if (permission === 'device:update') return <PermissionAction key={permission} permission={permission} testId="rename-device" onClick={() => rename(device)}>{label}</PermissionAction>; if (permission === 'device:provision') return <PermissionAction key={permission} permission={permission} testId="decommission-device" onClick={() => remove(device)}>{label}</PermissionAction>; if (permission === 'device:file_transfer') return <PermissionAction key={permission} permission={permission} testId="transfer-files">{label}</PermissionAction>; const mode = permission === 'device:view' ? 'view' : permission === 'device:control' ? 'control' : 'terminal'; return <PermissionAction key={permission} permission={permission} testId={`start-${mode}`} onClick={() => start(device.id, mode)}>{label}</PermissionAction>; })}</td></tr>)}</tbody></table></div>}</section>;
}

function PeopleView({ data, permissions, api, onChanged }) {
  const allowed = (permission) => permissions?.[permission]?.effect === 'allow';
  const [error, setError] = useState(null);
  const mutate = async (path, options) => { setError(null); try { await api.request(path, options); onChanged('people'); } catch (reason) { setError(reason); } };
  const invite = async () => { const email = window.prompt('Invite email'); if (!email) return; const role = window.prompt('Role', 'viewer'); if (!role) return; await mutate(`/orgs/${data.orgId}/invites`, { method: 'POST', body: { email, role } }); };
  return <section className="view"><div className="view-heading"><div><p className="eyebrow">DIRECTORY / MEMBERS</p><h2>People</h2></div>{allowed('user:invite') && <PermissionAction permission="user:invite" testId="invite-user" onClick={invite}>Invite user</PermissionAction>}</div>{error && <div className="error" role="alert">{displayError(error)}</div>}<div className="table-wrap"><table><thead><tr><th>Person</th><th>Role</th><th>Status</th><th>Controls</th></tr></thead><tbody>{(data.members || []).map((member) => <tr data-testid="user-row" data-user-id={member.userId} key={member.userId}><td><strong>{member.name}</strong><small>{member.email}</small></td><td>{member.role}</td><td>{member.status}</td><td className="actions">{allowed('user:role:update') && member.userId !== data.userId && <PermissionAction permission="user:role:update" testId="role-select" onClick={() => { const role = window.prompt('New role', member.role); if (role) mutate(`/orgs/${data.orgId}/members/${member.userId}`, { method: 'PATCH', body: { role } }); }}>Change role</PermissionAction>}{allowed('user:remove') && member.userId !== data.userId && <PermissionAction permission="user:remove" testId="suspend-user" onClick={() => mutate(`/orgs/${data.orgId}/members/${member.userId}/suspend`, { method: 'POST' })}>{member.status === 'suspended' ? 'Reinstate' : 'Suspend'}</PermissionAction>}{allowed('user:remove') && member.userId !== data.userId && <PermissionAction permission="user:remove" testId="remove-user" onClick={() => mutate(`/orgs/${data.orgId}/members/${member.userId}`, { method: 'DELETE' })}>Remove</PermissionAction>}</td></tr>)}</tbody></table></div></section>;
}

function GrantsView({ data, permissions, api, onChanged }) {
  const [form, setForm] = useState({ userId: '', deviceId: '', effect: 'allow', permissions: [] });
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(null);
  const allowed = (permission) => permissions?.[permission]?.effect === 'allow';
  const catalogue = data.devices?.[0]?.permissions ? Object.keys(data.devices[0].permissions) : [];
  const submit = async (event) => { event.preventDefault(); setError(null); try { await api.request(`/orgs/${data.orgId}/grants`, { method: 'POST', body: { ...form, deviceId: form.deviceId || null } }); setOpen(false); setForm({ userId: '', deviceId: '', effect: 'allow', permissions: [] }); onChanged('grants'); } catch (reason) { setError(reason); } };
  const revoke = async (id) => { try { await api.request(`/orgs/${data.orgId}/grants/${id}`, { method: 'DELETE' }); onChanged('grants'); } catch (reason) { setError(reason); } };
  return <section className="view"><div className="view-heading"><div><p className="eyebrow">AUTHORITY / GRANTS</p><h2>Grants</h2></div>{allowed('grant:create') && <PermissionAction permission="grant:create" testId="new-grant" onClick={() => setOpen(!open)}>New grant</PermissionAction>}</div>{error && <div className="error" role="alert">{displayError(error)}</div>}{open && <form className="inline-form" onSubmit={submit}><label>User<select data-testid="grant-user" value={form.userId} onChange={(event) => setForm({ ...form, userId: event.target.value })}><option value="">Select a member</option>{(data.members || []).filter((member) => member.status === 'active' && member.userId !== data.userId).map((member) => <option key={member.userId} value={member.userId}>{member.name}</option>)}</select></label><label>Device<select data-testid="grant-device" value={form.deviceId} onChange={(event) => setForm({ ...form, deviceId: event.target.value })}><option value="">All devices</option>{(data.devices || []).map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label><label>Effect<select data-testid="grant-effect" value={form.effect} onChange={(event) => setForm({ ...form, effect: event.target.value })}><option value="allow">Allow</option><option value="deny">Deny</option></select></label><div className="checks">{catalogue.map((permission) => <label className="check" key={permission}><input type="checkbox" data-permission-key={permission} checked={form.permissions.includes(permission)} onChange={(event) => setForm({ ...form, permissions: event.target.checked ? [...form.permissions, permission] : form.permissions.filter((item) => item !== permission) })} />{permission}</label>)}</div><button className="primary" data-testid="grant-submit" type="submit">Create grant</button></form>}<div className="table-wrap"><table><thead><tr><th>Grant</th><th>Recipient</th><th>Scope</th><th>Effect</th><th /></tr></thead><tbody>{(data.grants || []).map((grant) => <tr data-testid="grant-row" data-effect={grant.effect} key={grant.id}><td><strong>{grant.id}</strong><small>{grant.permissions.join(', ')}</small></td><td>{grant.userId}</td><td>{grant.deviceId || 'Organization'}</td><td><span className={grant.effect === 'allow' ? 'status online' : 'status danger'}>{grant.effect}</span></td><td>{allowed('grant:revoke') && <PermissionAction permission="grant:revoke" testId="revoke-grant" onClick={() => revoke(grant.id)}>Revoke</PermissionAction>}</td></tr>)}</tbody></table></div></section>;
}

function SessionsView({ data, permissions, api, onChanged }) {
  const [error, setError] = useState(null);
  const terminate = async (session) => { try { await api.request(`/sessions/${session.id}`, { method: 'DELETE' }); onChanged('sessions'); } catch (reason) { setError(reason); } };
  return <section className="view"><div className="view-heading"><div><p className="eyebrow">ACTIVITY / SESSIONS</p><h2>Sessions</h2></div></div>{error && <div className="error" role="alert">{displayError(error)}</div>}<div className="table-wrap"><table><thead><tr><th>Session</th><th>Mode</th><th>State</th><th>Expires</th><th /></tr></thead><tbody>{(data.sessions || []).map((session) => <tr data-testid="session-row" key={session.id}><td><strong>{session.id}</strong><small>{session.device_id} / {session.user_id}</small></td><td>{session.mode}</td><td>{session.state}{session.end_reason ? ` / ${session.end_reason}` : ''}</td><td>{session.expires_at}</td><td>{session.state === 'active' && (session.user_id === data.userId || permissions?.['session:terminate']?.effect === 'allow') && <PermissionAction permission={session.user_id === data.userId ? undefined : 'session:terminate'} testId="stop-session" onClick={() => terminate(session)}>Stop</PermissionAction>}</td></tr>)}</tbody></table></div></section>;
}

function AuditView({ data }) {
  return <section className="view"><div className="view-heading"><div><p className="eyebrow">TRACE / AUDIT LOG</p><h2>Audit</h2></div></div><div className="table-wrap"><table><thead><tr><th>Action</th><th>Target</th><th>Result</th><th>Reason</th><th>Request</th><th>At</th></tr></thead><tbody>{(data.events || []).map((event) => <tr data-testid="audit-row" key={event.id}><td>{event.action}</td><td>{event.target_type} / {event.target_id}</td><td><span className={event.result === 'allow' ? 'status online' : 'status danger'}>{event.result}</span></td><td>{event.reason_code || '—'}</td><td>{event.request_id || '—'}</td><td>{event.at}</td></tr>)}</tbody></table></div></section>;
}

function Invites({ data, permissions, api, onChanged }) {
  const [error, setError] = useState(null);
  const allowed = permissions?.['user:invite']?.effect === 'allow';
  const create = async () => { const email = window.prompt('Invite email'); if (!email) return; const role = window.prompt('Role', 'viewer'); if (!role) return; try { await api.request(`/orgs/${data.orgId}/invites`, { method: 'POST', body: { email, role } }); onChanged(data.orgId); } catch (reason) { setError(reason); } };
  useEffect(() => { if (allowed) api.request(`/orgs/${data.orgId}/invites`).then((result) => data.setInvites(result.invites)).catch(setError); }, [data.orgId, allowed]);
  return <article><div className="subheading"><div><span className="eyebrow">ACCESS / INVITES</span><h3>Invitations</h3></div>{allowed && <PermissionAction permission="user:invite" testId="invite-user" onClick={create}>Invite user</PermissionAction>}</div>{error && <div className="error" role="alert">{displayError(error)}</div>}<div className="invite-list">{(data.invites || []).map((invite) => <div className="invite-item" key={invite.id}><span>{invite.email}</span><small>{invite.role} · {invite.acceptedAt ? 'accepted' : invite.revokedAt ? 'revoked' : 'pending'}</small></div>)}</div></article>;
}

function AdminView({ data, permissions, api, onOrgCreated }) {
  const [error, setError] = useState(null);
  const allowed = (permission) => permissions?.[permission]?.effect === 'allow';
  const create = async () => { const name = window.prompt('Organization name'); if (!name) return; try { const result = await api.request('/orgs', { method: 'POST', body: { name } }); await onOrgCreated(result.id); } catch (reason) { setError(reason); } };
  const rename = async () => { const name = window.prompt('Organization name', data.org.name); if (!name) return; try { await api.request(`/orgs/${data.org.id}`, { method: 'PATCH', body: { name } }); await onOrgCreated(data.org.id); } catch (reason) { setError(reason); } };
  const remove = async () => { if (!window.confirm(`Delete ${data.org.name}?`)) return; try { await api.request(`/orgs/${data.org.id}`, { method: 'DELETE' }); window.location.reload(); } catch (reason) { setError(reason); } };
  return <section className="view"><div className="view-heading"><div><p className="eyebrow">ADMINISTRATION / ORGANIZATION</p><h2>{data.org.name}</h2></div><button className="primary" data-testid="create-org" onClick={create} type="button">Create organization</button></div>{error && <div className="error" role="alert">{displayError(error)}</div>}<div className="admin-grid"><article><span className="eyebrow">ACTIVE ORGANIZATION</span><h3>{data.org.name}</h3><p className="muted">Theme: {data.org.theme} · Session limit: {data.org.max_session_minutes} minutes</p>{allowed('org:update') && <PermissionAction permission="org:update" testId="rename-org" onClick={rename}>Rename organization</PermissionAction>}{allowed('org:delete') && <PermissionAction permission="org:delete" testId="delete-org" onClick={remove}>Delete organization</PermissionAction>}</article><Invites data={data} permissions={permissions} api={api} onChanged={onOrgCreated} /></div></section>;
}

function App({ api }) {
  const [session, setSession] = useState(null);
  const [booting, setBooting] = useState(true);
  const [view, setView] = useState('devices');
  const [data, setData] = useState({});
  const [error, setError] = useState(null);
  const invitePage = window.location.pathname.startsWith('/invite/');
  const loadMe = async () => { const me = await api.request('/auth/me'); setSession(me); return me; };
  const setInvites = (invites) => setData((previous) => ({ ...previous, invites }));
  useEffect(() => { if (invitePage) { setBooting(false); return; } api.refresh().then(loadMe).catch(() => {}).finally(() => setBooting(false)); }, []);
  useEffect(() => {
    if (!session) return;
    const orgId = session.org.id;
    const load = async () => {
      setError(null);
      try {
        const result = { orgId, org: session.org, userId: session.user.id, setInvites };
        if (view === 'devices') result.devices = (await api.request(`/orgs/${orgId}/devices`)).devices;
        if (view === 'people' || view === 'grants') result.members = (await api.request(`/orgs/${orgId}/members`)).members;
        if (view === 'grants') { result.grants = (await api.request(`/orgs/${orgId}/grants`)).grants; result.devices = (await api.request(`/orgs/${orgId}/devices`)).devices; }
        if (view === 'sessions') result.sessions = (await api.request(`/orgs/${orgId}/sessions`)).sessions;
        if (view === 'audit') result.events = (await api.request(`/orgs/${orgId}/audit?limit=100`)).events;
        setData((previous) => ({ ...previous, ...result }));
      } catch (reason) { setError(reason); }
    };
    load();
  }, [session, view]);
  const refreshView = (nextView = view) => { if (nextView !== view) setView(nextView); else setSession({ ...session }); };
  const login = async () => { const me = await loadMe(); setView('devices'); setData({ orgId: me.org.id, org: me.org, userId: me.user.id, setInvites }); };
  const switchOrg = async (orgId) => { try { const result = await api.request('/auth/token', { method: 'POST', body: { orgId } }); api.setToken(result.token); const me = await loadMe(); setView('devices'); setData({ orgId: me.org.id, org: me.org, userId: me.user.id, setInvites }); } catch (reason) { setError(reason); } };
  const createOrganization = async () => { const name = window.prompt('Organization name'); if (!name) return; try { const result = await api.request('/orgs', { method: 'POST', body: { name } }); await createOrgComplete(result.id); } catch (reason) { setError(reason); } };
  const createOrgComplete = async (orgId) => { const result = await api.request('/auth/token', { method: 'POST', body: { orgId } }); api.setToken(result.token); const me = await loadMe(); setView('devices'); setData({ orgId: me.org.id, org: me.org, userId: me.user.id, setInvites }); };
  const logout = () => { api.clearToken(); setSession(null); setData({}); };
  if (invitePage) return <InvitePage api={api} />;
  if (booting) return <main className="loading"><span className="eyebrow">REMOTEOPS</span><h1>Loading workspace...</h1></main>;
  if (!session) return <Login api={api} onLogin={login} />;
  const shellStyle = { backgroundColor: themes[session.org.theme] || themes.teal };
  const viewData = { ...data, org: session.org, orgId: session.org.id, userId: session.user.id, setInvites };
  return <main className="app-shell" data-testid="app-shell" data-org-id={session.org.id} data-org-theme={session.org.theme} style={shellStyle}><aside className="sidebar"><div className="brand"><span className="brand-mark">R</span><div><strong>RemoteOps</strong><small>Control plane</small></div></div><div className="org-switcher"><span className="eyebrow">CURRENT ORGANIZATION</span>{session.orgs.map((org) => <button className={org.id === session.org.id ? 'org-option selected' : 'org-option'} data-testid="org-option" data-org-id={org.id} key={org.id} onClick={() => switchOrg(org.id)} type="button"><span><strong>{org.name}</strong><small>{org.theme}</small></span><span aria-hidden="true">{org.id === session.org.id ? '●' : '○'}</span></button>)}<button className="create-org" data-testid="create-org" onClick={createOrganization} type="button">+ Create organization</button></div><Nav permissions={session.permissions} view={view} setView={setView} /><div className="sidebar-footer"><span className="eyebrow">SIGNED IN AS</span><strong data-testid="active-role">{session.role}</strong><button className="signout" onClick={logout} type="button">Sign out</button></div></aside><section className="content"><header className="topbar"><div><span className="eyebrow">WORKSPACE / {session.org.name.toUpperCase()}</span><h1>{view === 'admin' ? 'Administration' : view[0].toUpperCase() + view.slice(1)}</h1></div><div className="identity"><span className="identity-dot" />{session.user.name}</div></header>{error && <div className="error page-error" role="alert">{displayError(error)}</div>}{view === 'devices' && <DevicesView data={viewData} permissions={session.permissions} api={api} onChanged={refreshView} />}{view === 'people' && <PeopleView data={viewData} permissions={session.permissions} api={api} onChanged={refreshView} />}{view === 'grants' && <GrantsView data={viewData} permissions={session.permissions} api={api} onChanged={refreshView} />}{view === 'sessions' && <SessionsView data={viewData} permissions={session.permissions} api={api} onChanged={refreshView} />}{view === 'audit' && <AuditView data={viewData} />}{view === 'admin' && <AdminView data={viewData} permissions={session.permissions} api={api} onOrgCreated={createOrgComplete} />}</section></main>;
}

function Root() {
  const api = useApi();
  return <App api={api} />;
}

createRoot(document.getElementById('root')).render(<Root />);
