"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import { socialmedia, urls } from "@/assets/data/mock";
import Logo from "../../../Logo";
import { useState } from "react";
import MobileMenu from "./mobileMenu";
import { FaBars } from "react-icons/fa";
import { useSession } from "next-auth/react";

const Navbar = () => {
  const { data: session } = useSession()

  const pathname = usePathname();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen);
  };

  return (
    <header className=" max-sm:hidden w-full px-20 py-5 text-white font-medium flex item-center justify-between relative print:hidden bg-gray-600">
      <nav className="flex capitalize items-center gap-4 ">
        {urls.map((url) => (
          <Link href={`${url?.url}`} className={`relative group`} key={url.id}>
            {url?.text}
            <span
              className={`h-[1px] inline-block bg-white absolute left-0 -bottom-0.5 group-hover:w-full transition-[width] ease-in duration-300 ${pathname === url.url ? "w-full" : "w-0"
                }`}
            >
              &nbsp;
            </span>
          </Link>
        ))}
      </nav>

      <nav className="flex items-center gap-3 xs:hidden  md:flex">
        {socialmedia.map((social) => (
          <motion.a key={social.id} target="_blank" href={`${social.url}`} whileHover={{ y: -2 }} whileTap={{ scale: 0.9 }}>
            {social.icon}
          </motion.a>
        ))}
        {session && <Link href={'/dashboard'}>Dashboard</Link>}
      </nav>

      <div className=" absolute left-[50%] top-2 translate-x-[-50%] ">
        <Logo />
      </div>
      <div className="md:hidden ">

        <button onClick={toggleMenu}><FaBars /></button>

        {isMenuOpen && <MobileMenu isOpen={isMenuOpen} toggleMenu={toggleMenu} />}

      </div>
    </header>
  );
};

export default Navbar;
