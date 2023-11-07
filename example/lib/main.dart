import 'dart:async';
import 'dart:io';

import 'package:ffigen_cryptolib/ffigen_cryptolib.dart' as ffigen_cryptolib;
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  late int sumResult;
  late Future<int> sumAsyncResult;
  String test = 'test';

  @override
  void initState() {
    super.initState();
    sumResult = ffigen_cryptolib.sum(1, 2);
    sumAsyncResult = ffigen_cryptolib.sumAsync(3, 4);
    test = ffigen_cryptolib.printString("Hello world");
  }

  @override
  Widget build(BuildContext context) {
    const textStyle = TextStyle(fontSize: 25);
    const spacerSmall = SizedBox(height: 10);
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Native Packages'),
        ),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Column(
              children: [
                const Text(
                  'This calls a native function through FFI that is shipped as source in the package. '
                  'The native code is built as part of the Flutter Runner build.',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
                Text(
                  'sum(1, 2) = $sumResult',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
                FutureBuilder<int>(
                  future: sumAsyncResult,
                  builder: (BuildContext context, AsyncSnapshot<int> value) {
                    final displayValue =
                        (value.hasData) ? value.data : 'loading';
                    return Text(
                      'await sumAsync(3, 4) = $displayValue',
                      style: textStyle,
                      textAlign: TextAlign.center,
                    );
                  },
                ),
                spacerSmall,
                InkWell(
                  onTap: () async {
                    // setState(() {
                    //   test = ffigen_cryptolib.printString("Hello world");
                    // });
                    var status = await Permission.storage.status;
                    if (!status.isGranted) {
                      await Permission.storage.request();
                    }
                    if (status.isGranted) {
                      FilePickerResult? result =
                          await FilePicker.platform.pickFiles();

                      if (result != null) {
                        String? path = await getPath();
                        print('path: $path');
                        if (path == null) {
                          print('path is null');
                          return;
                        }
                        String fileOutput = 'output.dec';
                        fileOutput = '$path/${getFileName(path, fileOutput)}';
                        print(fileOutput);
                        String? check = ffigen_cryptolib.printFile(
                            result.files.single.path!, fileOutput);
                        print('check: $check');
                      }
                    }
                  },
                  child: Text(
                    test,
                    style: textStyle,
                    textAlign: TextAlign.center,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<String?> getPath() async {
    Directory? directory;
    String path = "";
    try {
      if (Platform.isAndroid) {
        directory = await getExternalStorageDirectory();
        List<String> paths = directory!.path.split("/");
        for (int i = 1; i < paths.length; i++) {
          String folder = paths[i];
          if (folder != "Android") {
            path += "/$folder";
          } else {
            break;
          }
        }
        path = "$path/Download"; // lưu ở thư mục download android
        // nếu muốn lưu ở thư mục Documents thì thay Download thành Documents
      } else {
        directory = await getApplicationSupportDirectory(); // iOS
      }
      return path;
    } catch (e) {
      print(e);
      return null;
    }
  }

  /// check file đã tồn tại thì gắn thêm _num
  getFileName(String path, String fileName) {
    int num = 0;
    var split = fileName.split('.');
    String pathFile = "$path/$fileName";

    while (File(pathFile).existsSync()) {
      /// check file exits
      num++;
      fileName = '${split[0]}($num).${split[1]}';
      pathFile = "$path/$fileName";
    }
    return fileName;
  }
}
