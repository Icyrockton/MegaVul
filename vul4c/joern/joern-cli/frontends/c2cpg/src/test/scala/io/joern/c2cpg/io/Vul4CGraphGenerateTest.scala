package io.joern.c2cpg.io

import io.joern.c2cpg.parser.FileDefaults
import io.joern.c2cpg.testfixtures.{C2CpgFrontend, CCodeToCpgSuite, DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.Cpg
import java.io.File
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.{ExecutorService, Executors, LinkedBlockingQueue, ThreadPoolExecutor, TimeUnit}

import org.json4s._
import org.json4s.native.JsonMethods._
import org.json4s.native.{Serialization, compactJson}


class Vul4C_C_TestCpg extends DataFlowTestCpg {
  /** A standard file extension for the source code files of the given language. E.g. `.c` for C language
    */
  override val fileSuffix: String = FileDefaults.C_EXT
}

class Vul4C_CPP_TestCpg extends DataFlowTestCpg {
  /** A standard file extension for the source code files of the given language. E.g. `.cpp` for CPP language
    */
  override val fileSuffix: String = FileDefaults.CPP_EXT
}


class Vul4CGraphGenerateTest extends DataFlowCodeToCpgSuite {

  def importCode(inputFilePath: String): Cpg = {
    val content = Files.readString(Paths.get(inputFilePath))
    if (inputFilePath.endsWith(".c")) {
      return new Vul4C_C_TestCpg().moreCode(content)
    }
    else if (inputFilePath.endsWith(".cpp")) {
      return new Vul4C_CPP_TestCpg().moreCode(content)
    }
    else
      throw new Exception(s"${inputFilePath} suffix can't recognized, only support .c or .cpp suffix")
  }

  def generateGraphForThisFunction(function_dir_path: Path): Unit = {
    val file_name = function_dir_path.getFileName.toString
    val save_json_dst = function_dir_path.resolve(s"${file_name}.json")
    if (Files.exists(save_json_dst) && save_json_dst.toFile.length() != 0 ){
      return
    }

    val func_path = if (Files.exists(function_dir_path.resolve(s"${file_name}.c"))) {
      function_dir_path.resolve(s"${file_name}.c")
    } else {
      function_dir_path.resolve(s"${file_name}.cpp")
    }

    val cpg = importCode(func_path.toString)
    val nodes = parse(cpg.graph.V().map(node => node).toJson)
    val edges = parse(cpg.graph.E().map(node => Map("inNode" -> node.inNode.id(), "outNode" -> node.outNode().id(), "etype" -> node.label(), "variable" -> node.property("VARIABLE"))).toJson)
    val final_map = Map("nodes" -> nodes, "edges" -> edges)
    implicit val formats = DefaultFormats
    val final_string = Serialization.write(final_map)
    Files.writeString(save_json_dst, final_string)
  }


  def generateGraphForCommit(commit: String): Unit = {
    val commit_dir = new File(commit)
    val commit_files = commit_dir.listFiles()
    for (commit_file <- commit_files) {
      val vul_before_func_path = commit_file.toPath.resolve("vul/before")
      val vul_after_func_path = commit_file.toPath.resolve("vul/after")
      val non_vul_func_path = commit_file.toPath.resolve("non_vul")
      if (Files.exists(vul_before_func_path))
        Files.list(vul_before_func_path).forEach({ func => generateGraphForThisFunction(func) })
      if (Files.exists(vul_after_func_path))
        Files.list(vul_after_func_path).forEach({ func => generateGraphForThisFunction(func) })
      if (Files.exists(non_vul_func_path))
        Files.list(non_vul_func_path).forEach({ func => generateGraphForThisFunction(func) })

    }
  }


  "generateGraph" should {
    println("Hello")
    println(sys.props)
    println(sys.env)
    if (!sys.env.contains("Vul4CInputDir")) {
      throw new RuntimeException("Vul4CInputDir environment variable missing...")
    }
    val indexFile: File = new File(sys.env("Vul4CInputDir"), "Vul4C_index.json")
    val indexContent = Files.readString(indexFile.toPath)
    val json = parse(indexContent)
    val commit_list = json.values.asInstanceOf[List[String]]

    val threads = Runtime.getRuntime.availableProcessors()
    val executorService: ExecutorService = Executors.newFixedThreadPool(threads)
    println(s"Running In $threads Threads")
    val batchSize = commit_list.length / threads
    val reportStep = (batchSize * 0.1).toInt
    (0 until threads).foreach { threadId =>
      val start = threadId * batchSize
      val end = if (threadId == threads - 1) commit_list.length else (threadId + 1) * batchSize
      val total = end - start
      executorService.execute(() => {
        println(s"Starting Thread-$threadId Process $total Commits.")
        try {
          for (i <- start until end) {
            val current_step = i - start
            generateGraphForCommit(commit_list(i))
            if (current_step % reportStep == 0 && current_step != 0) {
              println(s"[Thread-$threadId] Progress: $current_step / $total Commits")
            }
          }
        } catch {
          case e:OutOfMemoryError => {
            println(s"[Thread-$threadId] OutOfMemoryError found! need run Joern again")
          }
        }
        finally {
          println(s"[Thread-$threadId] Done")
        }
      })
    }

        Runtime.getRuntime.addShutdownHook(new Thread(new Runnable {
          override def run(): Unit = {
            println("Shutdown Hook activated. Cancelling all threads...")
            executorService.shutdown()
            try {
              if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow()
              }
            } catch {
              case e: InterruptedException =>
                executorService.shutdownNow()
            }
            println("All threads cancelled. Shutdown successful.")
          }
        }))

    executorService.shutdown()
    executorService.awaitTermination(Long.MaxValue, TimeUnit.HOURS)
    println("Vul4C Generate Graph Done!")
  }
}
