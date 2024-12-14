import ForgetPassword from "@/components/page/public/ForgetPassword";
import Link from "next/link";

const Index = () => {
  return (
    <div className="min-h-screen flex items-center  flex-col justify-center bg-gray-100">
     <div className="mt-5"><Link href={'/'} >Go to Homepage</Link></div>
      <ForgetPassword/>
    </div>
  );
};

export default Index;
