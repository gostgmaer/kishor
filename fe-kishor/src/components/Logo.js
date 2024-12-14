import { motion } from "framer-motion";
import Link from "next/link";

const MotionLink = motion(Link);

const Logo = () => {
  return (
    <motion.div className=" flex items-center justify-center mt-2">
      <MotionLink
        href={"/resume"}
        className=" w-16 h-16 bg-dark text-light flex justify-center items-center rounded-full font-bold text-xl"
        whileHover={{
          backgroundColor: [
            "#121212",
            "rgba(131,58,180,1)",
            "rgba(253,29,29,1)",
            "rgba(252,176,69,1)",
            "rgba(131,58,180,1)",
            "#121212",
          ],transition:{duration:1,repeat:Infinity}
        }}
      >
        KS
      </MotionLink>
    </motion.div>
  );
};

export default Logo;
