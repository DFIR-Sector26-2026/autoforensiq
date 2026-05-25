export default function Threats() {

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-6">
        Threat Intelligence
      </h1>

      <div className="space-y-4">

        <div className="
          bg-red-950
          border border-red-700
          rounded-xl
          p-4
        ">
          Injected code detected in winlogon.exe
        </div>

        <div className="
          bg-red-950
          border border-red-700
          rounded-xl
          p-4
        ">
          Suspicious lineage:
          {" "}
          tasksche.exe → WannaDecryptor
        </div>

      </div>

    </div>
  );
}
