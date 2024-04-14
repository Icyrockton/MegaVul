package io.joern.javasrc2cpg.querying

import io.joern.javasrc2cpg.JavaSrc2CpgTestContext
import io.joern.javasrc2cpg.testfixtures.{JavaSrcCode2CpgFixture}

import java.nio.file.{Files, Path, Paths}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.Cpg

import java.io.File
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.{ExecutorService, Executors, TimeUnit}
import org.json4s.*
import org.json4s.native.JsonMethods.*
import org.json4s.native.Serialization


class MegaVulGraphGenerateForJavaTest extends JavaSrcCode2CpgFixture {

  def importCode(inputFilePath: String): Cpg = {
    val content = Files.readString(Paths.get(inputFilePath))
    if (inputFilePath.endsWith(".java")) {
      return JavaSrc2CpgTestContext.buildCpgWithDataflow(s"public class Main { \n ${content} \n }")
    }
    else
      throw new Exception(s"${inputFilePath} suffix can't recognized, only support .java suffix")
  }


  def generateGraphForFunction(function_dir_path: Path): Unit = {
    val file_name = function_dir_path.getFileName.toString
    val save_json_dst = function_dir_path.resolve(s"${file_name}.json")
    if (Files.exists(save_json_dst) && save_json_dst.toFile.length() != 0) {
      return
    }

    val func_path = function_dir_path.resolve(s"${file_name}.java")


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
        Files.list(vul_before_func_path).forEach({ func => generateGraphForFunction(func) })
      if (Files.exists(vul_after_func_path))
        Files.list(vul_after_func_path).forEach({ func => generateGraphForFunction(func) })
      if (Files.exists(non_vul_func_path))
        Files.list(non_vul_func_path).forEach({ func => generateGraphForFunction(func) })
    }
  }


  "generateGraph" should {
    println(sys.env)
    if (!sys.env.contains("MegaVulInputDir")) {
      throw new RuntimeException("MegaVulInputDir environment variable missing...")
    }
    val indexFile: File = new File(sys.env("MegaVulInputDir"), "MegaVul_index.json")
    val indexContent = Files.readString(indexFile.toPath)
    val commit_list = parse(indexContent).values.asInstanceOf[List[String]]

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
          case e: OutOfMemoryError => {
            println(s"[Thread-$threadId] OutOfMemoryError found! need run Joern again")
          }
        }
        finally {
          println(s"[Thread-$threadId] Done")
        }
      })
    }

    executorService.shutdown()
    executorService.awaitTermination(Long.MaxValue, TimeUnit.HOURS)
    println("MegaVul Generate Java Graph Done!")
  }

}
