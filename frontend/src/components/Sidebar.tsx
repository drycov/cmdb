/**
 * Frontend module for components Sidebar.
 */
import { NavLink } from "react-router-dom";

const navItems = [
  { path: "/", label: "Обзор" },
  { path: "/inventory", label: "Инвентарь" },
  { path: "/operations", label: "Операции" },
  { path: "/topology", label: "Топология" },
];

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand">MikroTik SOT</div>
        <p className="brand-caption">
          Source of Truth, topology intelligence and operational visibility.
        </p>
      </div>
      <nav>
        <ul>
          {navItems.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                end={item.path === "/"}
                className={({ isActive }) =>
                  isActive ? "nav-link active" : "nav-link"
                }
              >
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
}

export default Sidebar;
/**
 * Main application navigation displayed across all frontend pages.
 */
