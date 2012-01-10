zynamics MSDN IDA Pro Plugin has moved to Google Code
=====================================================

This repository has moved to Google Code:
http://code.google.com/p/zynamics/source/checkout?repo=msdn-ida-plugin



zynamics ida-msdn 1.1 - Copyright 2010
For updates please check http://github.com/zynamics/msdn-plugin-ida

Using the zynamics ida-msdn IDA Pro plugin you can import Windows API
documentation from the MSDN into your IDA Pro IDB files.

1. Usage

- At first you have to extract MSDN documentation from a local installation
  of the MSDN. You can use the zynamics MSDN crawler for this which you can
  download from http://github.com/zynamics/msdn-crawler
- Once the MSDN crawler has generated the msdn.xml file you have to adjust
  the path to the msdn.xml file in ida_importer.py
- Using IDAPython 1.3.2 or higher you can then execute ida_importer.py

2. License

The MSDN crawler is licensed under the GPL 2.0 license. Please see gpl.txt for
more information.

3. Contributions

Thanks to the following people who have contributed code and ideas to make
ida-msdn better:

Mario Vilas