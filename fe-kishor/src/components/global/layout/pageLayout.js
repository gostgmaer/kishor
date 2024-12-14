import React from "react";
import Navbar from "../navbar/public/navbar";
import NavbarPublic from "../navbar/public/mobileMenu";

const PageLayout = ({ children }) => {
  return (
    <div className="content print:px-0 bg-gray-300 ">
      <NavbarPublic />
      <div className="element min-h-[calc(100vh-64px)] flex items-center">
        <div className="max-w-7xl  m-auto w-full">
          {children}
        </div>


      </div>
    </div>
  );
};

export default PageLayout;
