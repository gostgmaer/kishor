import Signup from "@/components/page/public/Register";
import Link from "next/link";

const Register = () => {


  return (
    <div className="min-h-screen flex items-center justify-center flex-col  bg-gray-100">
      <div className="mt-5"><Link href={'/'} >Go to Homepage</Link></div>
     <Signup/>
   
    </div>
  );
};

export default Register;
