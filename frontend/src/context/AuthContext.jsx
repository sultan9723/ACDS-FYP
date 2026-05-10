import React, { createContext, useContext, useState, useEffect } from "react";
import { loginUser, verifyToken, getUserProfile, logoutUser } from "../utils/api";

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem("authToken"));
  const [isLoading, setIsLoading] = useState(true);

  // Check if user is authenticated on mount
  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken = localStorage.getItem("authToken");
      const storedUser = localStorage.getItem("authUser");

      if (!storedToken || !storedUser) {
        setIsLoading(false);
        return;
      }

      try {
        const validation = await verifyToken();
        if (!validation?.valid) {
          localStorage.removeItem("authToken");
          localStorage.removeItem("authUser");
          setToken(null);
          setUser(null);
          setIsLoading(false);
          return;
        }

        const profile = await getUserProfile();
        const resolvedUser = profile?.user || JSON.parse(storedUser);

        localStorage.setItem("authUser", JSON.stringify(resolvedUser));
        setToken(storedToken);
        setUser(resolvedUser);
      } catch {
        localStorage.removeItem("authToken");
        localStorage.removeItem("authUser");
        setToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const login = async (email, password) => {
    try {
      const data = await loginUser(email, password);

      if (!data?.success || !data?.access_token || !data?.user) {
        return { success: false, error: data?.message || "Invalid credentials" };
      }

      localStorage.setItem("authToken", data.access_token);
      localStorage.setItem("authUser", JSON.stringify(data.user));

      setToken(data.access_token);
      setUser(data.user);

      return { success: true };
    } catch (error) {
      return { success: false, error: error.detail || error.message || "Login failed" };
    }
  };

  const logout = async () => {
    try {
      await logoutUser();
    } catch {
      // no-op: always clear local state on logout
    }
    localStorage.removeItem("authToken");
    localStorage.removeItem("authUser");
    setToken(null);
    setUser(null);
  };

  const isAuthenticated = !!token && !!user;

  const value = {
    user,
    token,
    isLoading,
    isAuthenticated,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;
