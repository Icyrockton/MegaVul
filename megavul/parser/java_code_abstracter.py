import logging
from typing import Callable
from tree_sitter import Node, Parser
from megavul.parser.code_abstracter_base import CodeAbstracterBase
from megavul.util.logging_util import global_logger

class JavaCodeAbstracter(CodeAbstracterBase):
    """
        this abstractor is used to abstract java methods
    """
    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self.parser = self.get_parser('java')

    @property
    def support_languages(self) -> list[str]:
        return ['java']

    def find_parser(self, language: str) -> Parser:
        return self.parser

    def abstract_node(self, node: Node, node_abstract: Callable[[Node, str], None],
                      abstract_type_map: dict[str, dict[str, str]]):
        node_type = node.type
        if node_type in ['identifier', 'type_identifier', ]:
            if node.parent is None or node.parent.type in ['method_declaration', 'class_declaration',
                                                           'constructor_declaration']:
                # keep function/class/constructor  name, we do not abstract these name
                return

            cur_type = 'VAR'

            if node.parent.type == 'method_invocation' and node.parent.child_by_field_name('name') == node:
                # function id
                cur_type = 'FUNC'
            elif node_type in ['type_identifier']:
                # do not abstract primitive data types: 'integral_type', 'floating_point_type', 'boolean_type'
                cur_type = 'TYPE'
            elif node.parent.type == 'labeled_statement':
                cur_type = 'LABEL'
            elif node.parent.type == 'field_access' and node.parent.child_by_field_name('field') == node:
                cur_type = 'FIELD'
            elif node.parent.type in ['annotation', 'marker_annotation']:
                cur_type = 'ANNOTATION'

            assert cur_type in abstract_type_map.keys()
            node_abstract(node, cur_type)
        elif node_type == 'string_literal':
            node_abstract(node, 'STR')
        elif node_type in ['block_comment', 'line_comment']:
            node_abstract(node, 'COMMENT')
        elif node_type in ['decimal_integer_literal', 'hex_integer_literal', 'octal_integer_literal',
                           'binary_integer_literal', 'decimal_floating_point_literal',
                           'hex_floating_point_literal', ]:
            node_abstract(node, 'NUMBER')
        elif node_type == 'character_literal':
            node_abstract(node, 'CHAR')


if __name__ == '__main__':
    abstracter = JavaCodeAbstracter(global_logger)
    print(abstracter.abstract_code("""
public class ClientHintsAnalyzer extends ClientHintsHeadersParser {

    public ClientHintsAnalyzer() {
        super();
    }

    /**
     * This is used to configure the provided Kryo instance if Kryo serialization is desired.
     * The expected type here is Object because otherwise the Kryo library becomes
     * a mandatory dependency on any project that uses Yauaa.
     *
     * @param kryoInstance The instance of com.esotericsoftware.kryo.Kryo that needs to be configured.
     */
    public static void configureKryo(AccessControlledResource.Priviledge... classes) {
    	// wdadw
        KKK.ss kryo = (Kryo) kryoInstance;
        char a ='a';
        int b = 20.00;
        A b = new A();
        A<String> b = new A();
        kryo.register(ClientHintsAnalyzer.class);
        ClientHintsHeadersParser.configureKryo(kryoInstance);
        sss:
        	for (;;) {
    for (;; i++) {
        if (i == 255) {
            break abc;
        }
    }
}
    }

    @AllArgsConstructor
    private static class OSFields implements Serializable {
        @Getter String name;              // Windows NT
        @Getter String version;           // 8.1
        @Getter String versionMajor;      // 8
        @Getter String nameVersion;       // Windows 8.1
        @Getter String nameVersionMajor;  // Windows 8
    }


    private void setCHBrandVersionsList(MutableUserAgent userAgent, String baseFieldName, ArrayList<Brand> brands) {
        if (brands != null) {
            int i = 0;
            for (Brand brand : brands) {
                userAgent.set(baseFieldName + '_' + i + "_Brand",   brand.getName(),   1);
                userAgent.set(baseFieldName + '_' + i + "_Version", brand.getVersion(), 1);
                i++;
            }
        }
    }

    
    public void improveOperatingSystem(MutableUserAgent userAgent, ClientHints clientHints) {
        // Improve the OS info.
        // https://wicg.github.io/ua-client-hints/#sec-ch-ua-platform
        // The Sec-CH-UA-Platform request header field gives a server information about the platform on which
        // a given user agent is executing. It is a Structured Header whose value MUST be a string [RFC8941].
        // Its value SHOULD match one of the following common platform values:
        // - "Android"
        // - "Chrome OS"
        // - "iOS"
        // - "Linux"
        // - "macOS"
        // - "Windows"
        // - "Unknown"
        String platform = clientHints.getPlatform();
        String platformVersion = clientHints.getPlatformVersion();
        if (platform != null && platformVersion != null && !platform.trim().isEmpty() && !platformVersion.trim().isEmpty()) {
//            MutableAgentField osName    = (MutableAgentField) userAgent.get(UserAgent.OPERATING_SYSTEM_NAME);
            String majorVersion = VersionSplitter.getInstance().getSingleSplit(platformVersion, 1);
            switch (platform) {
                case "macOS":
                    platform = "Mac OS";
                    overrideValue(userAgent.get(OPERATING_SYSTEM_NAME_VERSION_MAJOR), platform + " " + majorVersion);
                    break;

                case "Android":
                case "Chrome OS":
                case "iOS":
                case "Linux":
                    overrideValue(userAgent.get(OPERATING_SYSTEM_NAME_VERSION),       platform + " " + platformVersion);
                    overrideValue(userAgent.get(OPERATING_SYSTEM_NAME_VERSION_MAJOR), platform + " " + majorVersion);
                    break;

                case "Windows":
                    OSFields betterOsVersion = WINDOWS_VERSION_MAPPING.getLongestMatch(platformVersion);
                    if (betterOsVersion != null) {
                        overrideValue(userAgent.get(OPERATING_SYSTEM_NAME_VERSION_MAJOR), betterOsVersion.getNameVersionMajor());
                    }
                    break;

                case "Unknown":
                default:
                    platform = userAgent.getValue(OPERATING_SYSTEM_NAME);
                    overrideValue(userAgent.get(OPERATING_SYSTEM_VERSION), platformVersion);
                    overrideValue(userAgent.get(OPERATING_SYSTEM_VERSION_MAJOR), majorVersion);
                    overrideValue(userAgent.get(OPERATING_SYSTEM_NAME_VERSION), platform + " " + platformVersion);
                    overrideValue(userAgent.get(OPERATING_SYSTEM_NAME_VERSION_MAJOR), platform + " " + majorVersion);
                    break;
            }
        }
    }
}
}""", 'java')[0])
