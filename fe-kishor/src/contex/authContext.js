"use client";
import { parseCookies, setCookie } from "nookies";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { post } from "@/lib/http";
import { saveCookies, setToken, storeCookiesOfObject } from "@/helper/function";
import jwtDecode from "jwt-decode";
import Cookies from "js-cookie";
import { useSession } from "next-auth/react";
// import { useSession } from "next-auth/react";
export const AuthContext = React.createContext(null);

export const AuthContextProvider = ({ children }) => {


  const { data: session, status } = useSession();

  useEffect(() => {
    if (session) {
      if (session.user["accessToken"]) {
        const token = session.user["accessToken"].split(".");
        setToken("headerPayload", `${token[0]}.${token[1]}`, session.user["exp"]);
        setToken("signature", `${token[2]}`, session.user["exp"]);
      }
      storeCookiesOfObject(session["user"])
    }
  }, [session]);





  const [user, setUser] = React.useState(undefined);
  const [userId, setUserId] = useState(null);

  const router = useRouter();

  const handleLoginAuth = async (body) => {
    try {
      const res = await post("/authentication/user/signin", body);
      if (res["status"] = "OK") {
        if (res["access_token"]) {
          const cookies = saveCookies(res)
          setUser(cookies.userInfo);
          setUserId(cookies.access_token);
          return cookies.access_token;
        }
       
      }
    } catch (error) {
      console.log(error);
    }
  };

  const Logout = async () => {

    try {
      const res = await post("/authentication/user/signout");
      if (res.statusCode == "200") {
 
        window.sessionStorage.clear();
        window.localStorage.clear();
        const cookies = Cookies.get();
        for (const cookie in cookies) {
          Cookies.remove(cookie);
        }

        setUser(undefined);
        setUserId(undefined);
        router.push("/auth/login");
      }
    } catch (error) { }
  };

  // const unsubscribe = async () => {
  //   const cookiesData = Cookies.get();
  //   try {
     
  //     if (cookiesData.access_token) {
  //       const decodedToken = jwtDecode(cookiesData.access_token);
  //       setUserId(decodedToken);
  //       if (decodedToken["user_id"]) {
  //         const res = await post("/authentication/user/verify/auth-token");
  //         setUser(res);
  //       }
  //     }
  //   } catch (error) {
  //     setUser(undefined);
  //     setUserId(undefined);
  //   }
  // };
  // React.useEffect(() => {
  //   unsubscribe();
  // }, []);

  return (
    <AuthContext.Provider value={{ user, handleLoginAuth, Logout, userId }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuthContext = () => React.useContext(AuthContext);
