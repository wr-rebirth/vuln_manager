# 漏洞管理系统

一个基于 Vue 3 和 FastAPI 的漏洞管理系统，用于管理和追踪安全漏洞。

主要是为了解决一些小甲方客户或安全团队无法自研或采购漏洞管理平台，无法管理漏洞而开发的一个工具。

## 技术栈

### 前端

- Vue 3
- Element Plus UI框架
- ECharts 图表库
- Axios HTTP客户端

### 后端

- FastAPI
- SQLAlchemy ORM
- SQLite数据库
- Pandas (Excel文件处理)

## 使用

- 漏洞信息管理（增删改查）
- 数据导入导出（Excel格式）
- 多条件组合筛选、排序
- 实时数据统计和可视化
- 漏洞历史记录追踪
- 支持模糊搜索和精确匹配

### 界面

![img/image-20250509185457585](img/image-20250509185457585.png)

### 数据导入导出

-   下载模板
-   导入数据

![img/image-20250509190631242](img/image-20250509190631242.png)

-   数据模板

![img/image-20250509190756855](img/image-20250509190756855.png)

### 模糊匹配搜索

![img/image-20250509185607110](img/image-20250509185607110.png)

### 漏洞历史记录跟踪

-   会根据导入数据的资产/漏洞名称等信息生成唯一的vuln_Id
-   根据vuln_id后台生成漏洞历史记录表

![img/image-20250509185826850](img/image-20250509185826850.png)

## 设计思路

### 图表设计思路与实现

#### 图表设计

图表逻辑点：

关于该平台的数据分析图表设计理念如下，请根据漏洞历史记录表、通过增加第几次发现的字段（按照科学的方法设计，不一定要按照这个来）等来完成这几个图表的修改添加，请先给出设计想法不要直接修改：

-   漏洞等级分布图表：
    -   需要去除时间，并筛选出最后一次测试的漏洞状态为存在的漏洞数据做分析
-   月度发现漏洞的趋势图
    -   横轴为月份，竖轴为漏洞数量（同一个漏洞多次发现只能算一个，需要去除 时间与漏洞状态字段 后以第一次发现为准，不同月份的漏洞归属到第一次发现该漏洞的月份）
-   每月漏洞的发现、修复漏洞双条形-条形图
    -   增加一个双条形条形图，横轴为月份，竖轴为漏洞数量，双条形图分别是发现漏洞数量与修复漏洞数量，该数量需要去除漏洞状态字段，发现数量以第一次发现为准（不同月份归入第一次发现的月份，修复数量以以最后一次发现的漏洞状态为准）；
        1.   发现漏洞数量：当月漏洞

-    修复/未修复漏洞的占比饼图
    -   通过漏洞状态字段呈现修复/未修复漏洞的占比（需要去除 时间与漏洞状态字段 后，以最后一次发现的漏洞状态为准）

#### 实现：

##### 漏洞等级分布图表：

-   设计思路：

-   需要从 VulnerabilityHistory 表中获取每个漏洞的最新状态

-   使用 SQL 的窗口函数（ROW_NUMBER）按 vuln_id 分组，按 discovery_time 降序排序，获取最新记录

-   只统计状态为"存在"的漏洞

-   按 severity 字段分组统计数量

##### 月度发现漏洞趋势图：

-   设计思路：

-   需要从 VulnerabilityHistory 表中获取每个漏洞的首次发现时间

-   使用 SQL 的窗口函数，按 vuln_id 分组，按 discovery_time 升序排序，获取首次记录

-   按月份分组统计数量

-   横轴显示年月，纵轴显示漏洞数量

##### 每月漏洞发现/修复双条形图：

-   设计思路：

-   需要两个子查询：
    -   发现数量：使用窗口函数获取每个漏洞的首次发现时间
    -   修复数量：使用窗口函数获取每个漏洞的最新状态

-   按月份分组统计两个数量

-   使用不同颜色区分发现和修复数量

##### 修复/未修复漏洞占比饼图：

-   设计思路：

-   从 VulnerabilityHistory 表中获取每个漏洞的最新状态

-   使用窗口函数按 vuln_id 分组，按 discovery_time 降序排序

-   统计"存在"和"不存在"的数量

-   计算百分比

#### 数据结构设计

-   根据导入的漏洞和现有的漏洞数据生成复合字段Id,包括漏洞id，该字段在前端隐藏，生成漏洞历史记录表，增加漏洞发现时间字段，根据漏洞历史记录表归属到首次发现时间，并会伴随漏洞表的更新而刷新，增加功能漏洞详情到前端漏洞表的“操作”中，点击后可以查看漏洞的所有字段数据及漏洞历史记录条，如：

    ```shell
    # 漏洞id
    vuln_id  hash(
         vuln_name + 
         asset_ip + 
         asset_port + 
         target_url + 
         system + 
         customer
     )
    
    # 漏洞表（举例，基于现有字段扩充设计）
    Vulnerability (漏洞基本信息)
    - vuln_id (唯一标识，基于关键字段生成的哈希值)
    - vuln_name (漏洞名称)
    - severity (危险等级)
    - details (漏洞详情)
    - first_discovery_time (首次发现时间)
    - last_discovery_time (最后发现时间)
    - current_status (当前状态)
    - asset_info (资产信息JSON)
    - ip
    - port
    - url
    - system
    - customer
    - owner
    
    # 漏洞历史记录表（举例，基于现有字段扩充设计）
    VulnerabilityHistory (漏洞历史记录)
     - id (主键)
     - vuln_id (关联到Vulnerability)
     - discovery_time (发现时间)
     - status (当时状态)
     - source (发现来源)
     - remarks (备注)
    ```

## 环境要求

- Python 3.9+
- Node.js 16+
- npm 8+
- Docker 20.10+
- Docker Compose 2.0+

## 快速开始

### 1. 使用 Docker 部署（推荐）

#### 1.1 克隆项目

```bash
git clone https://github.com/wr-rebirth/vuln_manager.git
cd vuln_manager
```

#### 1.2 构建和启动容器
```bash
# 构建镜像并启动容器
docker-compose up -d

# 查看容器状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

#### 1.3 访问服务
- 前端页面：http://localhost:8080
- 后端API：http://localhost:8000
- API文档：http://localhost:8000/docs

#### 1.4 停止服务
```bash
# 停止容器
docker-compose down

# 停止容器并删除数据卷
docker-compose down -v
```

### 2. 手动部署

#### 2.1 后端部署

##### 2.1.1 创建虚拟环境
```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

##### 2.1.2 安装依赖
```bash
# 安装后端依赖
pip install fastapi
pip install uvicorn
pip install sqlalchemy
pip install pandas
pip install openpyxl
pip install python-multipart
```

##### 2.1.3 启动后端服务
```bash
# 进入后端目录
cd backend

# 默认端口启动（8000）
uvicorn main:app --reload

# 指定端口启动
uvicorn main:app --reload --port 8001
```

#### 2.2 前端部署

##### 2.2.1 安装依赖
```bash
# 进入前端目录
cd frontend

# 安装前端依赖
npm install
```

##### 2.2.2 启动开发服务器
```bash
# 开发模式启动
npm run serve

# 生产环境构建
npm run build
```

## Docker 配置说明

### 1. 目录结构
```
vuln_manager/
├── docker-compose.yml    # Docker Compose 配置文件
├── backend/
│   ├── Dockerfile       # 后端 Dockerfile
│   └── ...
├── frontend/
│   ├── Dockerfile       # 前端 Dockerfile
│   └── ...
└── ...
```

### 2. 环境变量配置
```env
# 后端环境变量
BACKEND_PORT8000
DATABASE_URLsqlite:///./vuln.db

# 前端环境变量
VUE_APP_API_URLhttp://localhost:8000
```

### 3. 数据持久化
- 数据库文件存储在 `./data` 目录
- 上传文件存储在 `./uploads` 目录

### 4. 网络配置
- 前端容器：8080端口
- 后端容器：8000端口
- 容器间通过内部网络通信

## 配置说明

### 后端配置

1. 数据库配置（backend/database.py）
```python
SQLALCHEMY_DATABASE_URL  "sqlite:///./vuln.db"
```

2. 端口配置（backend/main.py）
```python
# 默认端口为8000，可以通过启动命令修改
```

### 前端配置

1. API地址配置（frontend/src/views/VulnerabilityList.vue）
```javascript
// 修改API基础URL
const API_BASE_URL  "http://localhost:8000"
```

## 使用说明

### 1. 数据导入
- 点击"导入Excel"按钮
- 选择符合模板格式的Excel文件
- 系统会自动处理并导入数据

### 2. 数据筛选
- 支持多条件组合筛选
- 支持模糊搜索
- 支持精确匹配（如端口号）

### 3. 数据导出
- 点击"导出Excel"按钮
- 选择保存位置
- 导出当前筛选结果

### 4. 数据统计
- 漏洞等级分布
- 月度发现趋势
- 修复情况统计
- 状态分布

## 注意事项

### 数据安全
1. 定期备份数据库文件（vuln.db）
2. 生产环境建议使用更安全的数据库（如PostgreSQL）

### 性能优化
1. 大量数据导入时建议分批处理
2. 图表数据建议增加缓存机制
3. 生产环境部署时建议启用压缩

### 常见问题

1. 端口占用
```bash
# 检查端口占用
lsof -i :8000
# 修改端口
uvicorn main:app --reload --port 8001
```

2. 跨域问题
- 确保后端CORS配置正确
- 检查前端API地址配置

3. 数据导入失败
- 检查Excel文件格式是否符合模板要求
- 确保所有必填字段都已填写
- 检查日期格式是否正确

4. Docker相关问题
```bash
# 查看容器日志
docker-compose logs -f

# 重启服务
docker-compose restart

# 重建容器
docker-compose up -d --build

# 清理未使用的容器和镜像
docker system prune
```

## 更新日志

### v1.0.0
- 初始版本发布
- 基础功能实现
- 支持数据导入导出
- 支持数据统计和可视化

### v1.1.0
- 优化筛选功能
- 修复端口精确匹配问题
- 改进数据展示效果

### v1.2.0
- 添加Docker支持
- 优化部署流程
- 改进数据持久化

## 后续跟进

-   接入漏扫格式匹配，比如说可以导入或者接口调用漏洞数据，并提示需要补充的字段信息如归属客户等
-   根据配置文件来做监听IP、端口的配置

## 许可证

本项目采用 MIT 许可证，详情请查看 LICENSE 文件。 